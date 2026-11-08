//! A lightweight deadlock detector for the `mutex` and `semaphore` syscalls.
//!
//! To keep the change small, the detector is a standalone table owned by the
//! process rather than extra state inside `Mutex` / `Semaphore`.  For every
//! thread it only records how many units of each resource the thread holds and
//! which resource it is currently blocked on.  A request is then a depth-first
//! search over the resulting waits-for graph: blocking is refused when the
//! waiting chain cannot reach any thread that will not block (for a multi-unit
//! semaphore every holder of a unit is a candidate provider).
//!
//! Mutexes and semaphores are tracked separately; mixing them (or mixing them
//! with `waittid`) is out of scope, as allowed by the exercise.

use alloc::vec::Vec;

/// Accounting for one kind of resource (either all mutexes or all semaphores).
struct Bank {
    /// Total units of every resource.
    capacity: Vec<isize>,
    /// `alloc[tid][rid]`: units of resource `rid` currently held by `tid`.
    alloc: Vec<Vec<isize>>,
    /// Resource each thread is blocked on, `None` means it is not blocked.
    need: Vec<Option<usize>>,
}

impl Bank {
    fn new() -> Self {
        Self {
            capacity: Vec::new(),
            alloc: Vec::new(),
            need: Vec::new(),
        }
    }

    /// Make sure there is a row for `tid` and that every row is wide enough for
    /// `rid`.  All rows are kept at the same width.
    fn ensure(&mut self, tid: usize, rid: usize) {
        while self.alloc.len() <= tid {
            self.alloc.push(Vec::new());
            self.need.push(None);
        }
        if self.capacity.len() <= rid {
            self.capacity.resize(rid + 1, 0);
        }
        let width = self.capacity.len();
        for row in self.alloc.iter_mut() {
            if row.len() < width {
                row.resize(width, 0);
            }
        }
    }

    fn held(&self, rid: usize) -> isize {
        self.alloc.iter().map(|row| row[rid]).sum()
    }

    fn is_held(&self, rid: usize) -> bool {
        self.alloc.iter().any(|row| row[rid] > 0)
    }

    /// Can `tid` eventually finish?  `rid` overrides `need[tid]`, which lets us
    /// ask the question for a request that has not been taken yet.
    fn can_finish(&self, tid: usize, rid: Option<usize>, memo: &mut Vec<Option<bool>>) -> bool {
        if let Some(known) = memo[tid] {
            return known;
        }
        // mark as "cannot finish" while exploring: a cycle in the waits-for
        // graph is exactly the deadlock we are looking for
        memo[tid] = Some(false);
        let requesting = rid.is_some();
        let rid = match rid.or(self.need[tid]) {
            Some(rid) => rid,
            // nothing to wait for, the thread will run to completion
            None => {
                memo[tid] = Some(true);
                return true;
            }
        };
        // For a thread that is already waiting, a unit that nobody holds is either
        // free or already granted to it by `up()` (it just has not run yet), so it
        // will be woken up.  The request we are asked about must not use this
        // shortcut: that is exactly the request that would block.
        if !requesting && self.capacity[rid] > self.held(rid) {
            memo[tid] = Some(true);
            return true;
        }
        let mut ok = false;
        for holder in 0..self.alloc.len() {
            if holder == tid || self.alloc[holder][rid] <= 0 {
                continue;
            }
            if self.can_finish(holder, None, memo) {
                ok = true;
                break;
            }
        }
        memo[tid] = Some(ok);
        ok
    }

    /// Would `tid` blocking on one unit of `rid` create a deadlock?
    fn is_deadlock(&self, tid: usize, rid: usize) -> bool {
        let mut memo = Vec::new();
        memo.resize(self.alloc.len(), None);
        !self.can_finish(tid, Some(rid), &mut memo)
    }

    fn acquire(&mut self, tid: usize, rid: usize) {
        self.alloc[tid][rid] += 1;
        self.need[tid] = None;
    }

    fn release(&mut self, tid: usize, rid: usize) {
        if self.alloc[tid][rid] > 0 {
            self.alloc[tid][rid] -= 1;
        }
    }
}

/// Per-process deadlock detection state.
pub struct DeadlockDetector {
    mutex: Bank,
    sem: Bank,
}

impl DeadlockDetector {
    /// Create an empty detector (detection disabled until the syscall enables it).
    pub fn new() -> Self {
        Self {
            mutex: Bank::new(),
            sem: Bank::new(),
        }
    }

    /// Check a `mutex_lock` request.  Returns `false` if it would deadlock.
    pub fn mutex_lock_check(&mut self, tid: usize, rid: usize) -> bool {
        self.mutex.ensure(tid, rid);
        self.mutex.capacity[rid] = 1; // a mutex is a single-unit resource
        // free mutex: never blocks
        if !self.mutex.is_held(rid) {
            return true;
        }
        if self.mutex.is_deadlock(tid, rid) {
            return false;
        }
        self.mutex.need[tid] = Some(rid);
        true
    }

    /// Record that the mutex is now held by `tid`.
    pub fn mutex_acquired(&mut self, tid: usize, rid: usize) {
        self.mutex.ensure(tid, rid);
        self.mutex.capacity[rid] = 1;
        self.mutex.acquire(tid, rid);
    }

    /// Record that `tid` released the mutex.
    pub fn mutex_released(&mut self, tid: usize, rid: usize) {
        self.mutex.ensure(tid, rid);
        self.mutex.release(tid, rid);
    }

    /// Check a `semaphore_down` request, `count` being the current semaphore count.
    pub fn sem_down_check(&mut self, tid: usize, rid: usize, count: isize) -> bool {
        self.sem.ensure(tid, rid);
        // keep the capacity of the semaphore up to date (count + held = total)
        let total = count.max(0) + self.sem.held(rid);
        if total > self.sem.capacity[rid] {
            self.sem.capacity[rid] = total;
        }
        // resources left in the semaphore: no blocking needed
        if count > 0 {
            return true;
        }
        if self.sem.is_deadlock(tid, rid) {
            return false;
        }
        self.sem.need[tid] = Some(rid);
        true
    }

    /// Record that `tid` acquired one unit of the semaphore.
    pub fn sem_acquired(&mut self, tid: usize, rid: usize) {
        self.sem.ensure(tid, rid);
        self.sem.acquire(tid, rid);
    }

    /// Record that `tid` released one unit of the semaphore.
    pub fn sem_released(&mut self, tid: usize, rid: usize) {
        self.sem.ensure(tid, rid);
        self.sem.release(tid, rid);
    }
}
