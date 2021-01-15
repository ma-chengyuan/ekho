/*
Copyright 2021 Chengyuan Ma

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sub-
-license, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-
-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// A quick and dirty implementation of an efficient timer used to schedule packet (re)transmission
pub struct Timer(BinaryHeap<Reverse<u64>>);

impl Timer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(BinaryHeap::with_capacity(capacity))
    }

    pub fn schedule(&mut self, ts: u32, sn: u32) {
        self.0.push(Reverse(((ts as u64) << 32) | sn as u64));
    }

    pub fn imminent(&self) -> u32 {
        match self.0.peek() {
            Some(&Reverse(val)) => (val >> 32) as u32,
            None => u32::max_value(),
        }
    }

    pub fn event(&mut self, now: u32) -> Option<(u32, u32)> {
        let key = (now as u64 + 1) << 32;
        match self.0.peek() {
            Some(&Reverse(val)) if val < key => {
                let sn = val & (u32::max_value() as u64);
                let ts = val >> 32;
                self.0.pop();
                Some((ts as u32, sn as u32))
            }
            _ => None,
        }
    }
}
