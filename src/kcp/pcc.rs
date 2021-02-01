use super::{Segment, OVERHEAD};
use derivative::Derivative;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::cell::RefCell;
use std::rc::Rc;
use tinyvec::{array_vec, ArrayVec};
use tracing::debug;

#[derive(Clone, Debug, Deserialize, Derivative)]
#[derivative(Default)]
#[serde(default)]
pub struct Config {
    #[derivative(Default(value = "16.0"))]
    startup_rate: f64,
    #[derivative(Default(value = "10240.0"))]
    max_rate: f64,
    #[derivative(Default(value = "0.01"))]
    eps_min: f64,
    #[derivative(Default(value = "0.05"))]
    eps_max: f64,
    #[derivative(Default(value = "500.0"))]
    loss_coeff: f64,
    #[derivative(Default(value = "0.05"))]
    loss_tol: f64,
    #[derivative(Default(value = "10"))]
    mi_min_sends: usize,
}

#[derive(Default, Debug)]
pub(super) struct MonitorInterval {
    rate: f64,
    /// Acked traffic in bytes
    acked: usize,
    /// Lost traffic in bytes
    lost: usize,
    /// Sent traffic in packets
    sent: usize,
    ts_start: u32,
    min_duration: u32,
    ts_first_sent: Option<u32>,
    ts_last_sent: Option<u32>,
    useless: bool,
    waiting: u32,
}

#[derive(Default, Debug)]
struct UtilitySample {
    rate: f64,
    util: f64,
}

#[derive(Derivative)]
#[derivative(Debug)]
enum State {
    Starting {
        rate: f64,
        #[derivative(Debug = "ignore")]
        optimal: Option<UtilitySample>,
    },
    DecisionMaking {
        rate: f64,
        eps: f64,
        #[derivative(Debug = "ignore")]
        util_high: ArrayVec<[f64; 2]>,
        #[derivative(Debug = "ignore")]
        util_low: ArrayVec<[f64; 2]>,
        #[derivative(Debug = "ignore")]
        pending: ArrayVec<[f64; 4]>,
    },
    RateAdjusting {
        rate: f64,
        dir: i32,
        step: u32,
        #[derivative(Debug = "ignore")]
        optimal: UtilitySample,
    },
}

#[derive(Debug)]
pub(super) struct PCC {
    state: State,
    config: Config,
    mi_now: Rc<RefCell<MonitorInterval>>,
    mi_realign: bool,
}

impl State {
    fn decision_making(rate: f64, eps: f64) -> Self {
        let high = (1.0 + eps) * rate;
        let low = (1.0 - eps) * rate;
        let mut pending = array_vec!([f64; 4] => low, high, low, high);
        pending.shuffle(&mut thread_rng());
        Self::DecisionMaking {
            rate,
            eps,
            util_low: ArrayVec::default(),
            util_high: ArrayVec::default(),
            pending,
        }
    }
}

impl PCC {
    pub(super) fn new(config: Config, now: u32, rtt: u32) -> Self {
        PCC {
            state: State::Starting {
                rate: config.startup_rate,
                optimal: None,
            },
            mi_now: Rc::new(RefCell::new(MonitorInterval {
                min_duration: (thread_rng().gen_range(1.7..2.2) * rtt as f64).round() as u32,
                ts_start: now,
                ..Default::default()
            })),
            mi_realign: false,
            config,
        }
    }

    pub(super) fn update(&mut self, now: u32, rtt: u32) {
        let mi_expired = {
            let mi_now = self.mi_now.borrow();
            now > mi_now.ts_start + mi_now.min_duration && mi_now.sent >= self.config.mi_min_sends
        };
        if mi_expired || self.mi_realign {
            if self.mi_realign {
                self.mi_realign = false;
                self.mi_now.borrow_mut().useless = true;
            }
            let m = thread_rng().gen_range(1.7..2.2);
            let duration = (m * rtt as f64).round() as u32;
            let rate = match &mut self.state {
                State::Starting { rate, .. } => {
                    *rate *= 2.0;
                    rate.min(self.config.max_rate)
                }
                State::DecisionMaking { rate, pending, .. } => pending.pop().unwrap_or(*rate),
                State::RateAdjusting {
                    dir, step, rate, ..
                } => {
                    *step += 1;
                    *rate *= 1.0 + *step as f64 * *dir as f64 * self.config.eps_min;
                    rate.min(self.config.max_rate)
                }
            };
            self.mi_now = Rc::new(RefCell::new(MonitorInterval {
                ts_start: now,
                min_duration: duration,
                rate,
                ..Default::default()
            }))
        }
    }

    fn try_finish_mi(&mut self, mi: &Rc<RefCell<MonitorInterval>>) {
        let new_waiting = mi.borrow().waiting.saturating_sub(1);
        mi.borrow_mut().waiting = new_waiting;
        if new_waiting == 0 && !Rc::ptr_eq(&self.mi_now, mi) && !self.mi_now.borrow().useless {
            let mi = mi.borrow();
            let loss = (mi.lost as f64) / (mi.lost + mi.acked) as f64;
            // Note: if everything works fine, then the default values supplied in unwraps here
            // should never be used!
            let ts_first_sent = mi.ts_first_sent.unwrap_or(mi.ts_start);
            let ts_last_sent = mi.ts_last_sent.unwrap_or(mi.ts_start + mi.min_duration);
            let tput = mi.acked as f64 / (ts_last_sent - ts_first_sent) as f64;
            debug!("tput: {:.3}kBps {}-{}/{}", tput, ts_first_sent, ts_last_sent, mi.acked);
            let loss_penalty =
                1.0 / (1.0 + (-self.config.loss_coeff * (loss - self.config.loss_tol).exp()));
            let util = tput * (1.0 - loss_penalty);
            match &mut self.state {
                State::Starting { optimal: max_util, .. } => match max_util {
                    None => {
                        *max_util = Some(UtilitySample {
                            util,
                            rate: mi.rate,
                        })
                    }
                    Some(sample) if util > sample.util => {
                        *max_util = Some(UtilitySample {
                            util,
                            rate: mi.rate,
                        })
                    }
                    Some(sample) => {
                        self.state = State::decision_making(sample.rate, self.config.eps_min)
                    }
                },
                State::DecisionMaking {
                    rate,
                    eps,
                    util_high,
                    util_low,
                    ..
                } => {
                    if mi.rate > *rate {
                        let _ = util_high.try_push(util);
                    } else {
                        let _ = util_low.try_push(util);
                    }
                    if util_low.len() == 2 && util_high.len() == 2 {
                        // Random pairing: shuffling one vec is sufficient
                        util_low.shuffle(&mut thread_rng());
                        self.state = if util_low[0] > util_high[0] && util_low[1] > util_high[1] {
                            let rate = (1.0 - *eps) * *rate;
                            State::RateAdjusting {
                                dir: -1,
                                step: 0,
                                rate,
                                optimal: UtilitySample {
                                    util: (util_low[0] + util_low[1]) / 2.0,
                                    rate,
                                },
                            }
                        } else if util_low[0] < util_high[0] && util_low[1] < util_high[1] {
                            let rate = (1.0 + *eps) * *rate;
                            State::RateAdjusting {
                                dir: 1,
                                step: 0,
                                rate,
                                optimal: UtilitySample {
                                    util: (util_high[0] + util_high[1]) / 2.0,
                                    rate,
                                },
                            }
                        } else {
                            State::decision_making(
                                *rate,
                                self.config.eps_max.min(*eps + self.config.eps_min),
                            )
                        };
                        self.mi_realign = true;
                    }
                }
                State::RateAdjusting { optimal: max_util, .. } => {
                    if util < max_util.util {
                        self.state = State::decision_making(max_util.rate, self.config.eps_min);
                    } else {
                        *max_util = UtilitySample {
                            util,
                            rate: mi.rate,
                        }
                    }
                }
            }
        }
    }

    pub(super) fn on_ack(&mut self, seg: &Segment) {
        if let Some(mi) = &seg.mi {
            mi.borrow_mut().acked += seg.payload.len() + OVERHEAD as usize;
            self.try_finish_mi(mi);
        }
    }

    pub(super) fn on_loss(&mut self, seg: &mut Segment) {
        if let Some(mi) = &seg.mi {
            mi.borrow_mut().lost += seg.payload.len() + OVERHEAD as usize;
            self.try_finish_mi(mi);
        }
    }

    pub(super) fn rate(&self) -> f64 {
        self.mi_now.borrow().rate
    }

    pub(super) fn debug(&self) {
        debug!("{}kBps @ {:?}", self.rate(), self.state);
    }

    pub(super) fn prepare_send(&self, seg: &mut Segment) {
        {
            let mut mi = self.mi_now.borrow_mut();
            mi.waiting += 1;
            mi.sent += 1;
            if mi.ts_first_sent.is_none() {
                mi.ts_first_sent = Some(seg.ts);
            }
            mi.ts_last_sent = Some(seg.ts);
        }
        seg.mi = Some(self.mi_now.clone());
    }
}
