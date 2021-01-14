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

//! Linked Circular Array

#[derive(Debug)]
struct Element<T> {
    /// The index of its precedent, **MUST BE VALID AT ANY TIME.**
    prev: usize,
    /// The index of its successor, **MUST BE VALID AT ANY TIME.**
    next: usize,
    data: T,
}

/// Linked Circular Array, designed to efficiently support send/receive windows.
///
/// It supports
///
/// 1. O(1) access to element by key
/// 2. O(1) deletion to element by key
/// 3. O(1) peek to the front element ("front" means the first element inserted)
/// 4. Optimal complexity to traverse the precedents of a element
///
/// ...under the precondition that at any time, the range of keys at any time is upper-bounded by
/// a constant (as is the case in sliding windows).
#[derive(Debug)]
pub struct Window<T> {
    /// Size of the array, must be immutable
    size: usize,
    entry: Vec<Option<Element<T>>>,
    end: Option<usize>,
    len: usize,
}

// This default impl is meant to be used with `std::mem::take` only!
impl<T> Default for Window<T> {
    fn default() -> Self {
        Self::with_size(0)
    }
}

impl<T> Window<T> {
    pub fn with_size(size: usize) -> Self {
        Self {
            size,
            entry: (0..size).map(|_| None).collect(),
            end: None,
            len: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.end.is_none()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        match self.entry[index % self.size].as_mut() {
            Some(elem) => Some(&mut elem.data),
            None => None,
        }
    }

    pub fn push(&mut self, index: usize, data: T) {
        let index = index % self.size;
        if self.entry[index].is_some() {
            return;
        }
        self.entry[index] = Some(match self.end {
            Some(prev) => {
                let prev_elem = self.entry[prev].as_mut().unwrap();
                let next = prev_elem.next;
                prev_elem.next = index;
                self.entry[next].as_mut().unwrap().prev = index;
                Element { prev, next, data }
            }
            #[rustfmt::skip]
            None => Element { prev: index, next: index, data },
        });
        self.end = Some(index);
        self.len += 1;
    }

    pub fn remove(&mut self, index: usize) -> Option<T> {
        let index = index % self.size;
        let elem = self.entry[index].take()?;
        let (prev, next) = (elem.prev, elem.next);
        self.entry[index] = None;
        self.len -= 1;
        if index == self.end.unwrap() {
            if prev == index {
                self.end = None;
                return Some(elem.data);
            } else {
                self.end = Some(prev);
            }
        }
        self.entry[prev].as_mut().unwrap().next = next;
        self.entry[next].as_mut().unwrap().prev = prev;
        Some(elem.data)
    }

    pub fn contains(&self, index: usize) -> bool {
        self.entry[index].is_some()
    }

    pub fn front(&self) -> Option<&T> {
        self.end.map(|end| {
            let head = self.entry[end].as_ref().unwrap().next;
            &self.entry[head].as_ref().unwrap().data
        })
    }

    pub fn pop_unchecked(&mut self) -> T {
        let end = self.end.unwrap();
        let head = self.entry[end].as_ref().unwrap().next;
        self.remove(head).unwrap()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn for_preceding(&mut self, index: usize, mut action: impl FnMut(&mut T)) {
        let mut index = index % self.size;
        index = match self.entry[index].as_ref() {
            Some(elem) => elem.prev,
            None => return,
        };
        while index != self.end.unwrap() {
            let elem = self.entry[index].as_mut().unwrap();
            action(&mut elem.data);
            index = elem.prev;
        }
    }
}
