//! Events related functionality

use hashbrown::HashMap;
use smallvec::SmallVec;
use thiserror::Error;

use crate::{
    fd::{OwnedFd, RawFd},
    net::SocketFd,
    platform::{self, ImmediatelyWokenUp, RawMutex, RawMutexProvider, UnblockedOrTimedOut},
    utilities::array_index_map::{ArrayIndexMap, Index},
};

use alloc::sync::Arc;
use core::sync::atomic::Ordering::{Relaxed, SeqCst};

/// A maximum limit to the number of [`Waitable`]s that can be registered to an [`EventManager`].
///
/// This is mostly an arbitrary limit that can be bumped up if necessary, at the cost of using extra
/// memory in every [`EventManager`].
pub const CONFIG_MAX_WAITABLES: usize = 128;

/// The `EventManager` provides access to the ability to wait on events on files and sockets.
///
/// A LiteBox `EventManager` is parametric in the platform it runs on.
pub struct EventManager<Platform: platform::RawMutexProvider + 'static> {
    platform: &'static Platform,
    triggered_events: ArrayIndexMap<Arc<Platform::RawMutex>, CONFIG_MAX_WAITABLES>,
    // We use a `SmallVec` here to prevent unnecessary heap allocation for the common case of having
    // only a small number of `Waitable`s on a single `RawFd`. The number beyond which a heap
    // allocation occurs is a tradeoff between memory usage (wasted unused space) vs number of heap
    // allocations. For now, the chosen number is picked purely based on *vibes*.
    fd_to_indexes: HashMap<RawFd, SmallVec<[Index; 2]>>,
}

impl<Platform: platform::RawMutexProvider + 'static> EventManager<Platform> {
    /// Construct a new `EventManager` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `EventManager` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            triggered_events: ArrayIndexMap::new(),
            fd_to_indexes: HashMap::new(),
        }
    }
}

impl<Platform: platform::RawMutexProvider + 'static> EventManager<Platform> {
    /// Register interest in waiting on events.
    ///
    /// Returns a [`Waitable`] that supports a `wait` method to wait until the registered conditions
    /// are satisfied.
    #[must_use]
    pub fn register<'b>(&mut self, builder: &'b WaitableBuilder) -> Waitable<'b, Platform> {
        let rm = Arc::new(self.platform.new_raw_mutex());
        rm.underlying_atomic()
            .store(Events::empty().bits(), Relaxed);
        let index = self.triggered_events.insert(rm.clone());
        self.fd_to_indexes
            .entry(builder.raw_fd)
            .or_default()
            .push(index);
        Waitable { rm, builder, index }
    }

    /// Release registration. Note that this is a private function that is automatically invoked
    /// when a [`Waitable`] is dropped.
    fn unregister(&mut self, waitable: &Waitable<'_, Platform>) {
        self.triggered_events.remove(waitable.index).unwrap();
        let idxs = self
            .fd_to_indexes
            .get_mut(&waitable.builder.raw_fd)
            .unwrap();
        idxs.swap_remove(idxs.iter().position(|&idx| idx == waitable.index).unwrap());
        if idxs.is_empty() {
            self.fd_to_indexes.remove(&waitable.builder.raw_fd);
        }
    }

    /// Mark the `events` as occurring on `raw_fd`, causing any relevant wake-ups of any
    /// [`Waitable`]s that might be waiting on the `raw_fd`.
    ///
    /// Explicitly *not* exposed as a public API, but only as a crate-internal.
    pub(crate) fn mark_events(&self, raw_fd: RawFd, events: Events) {
        let Some(idxs) = self.fd_to_indexes.get(&raw_fd) else {
            return;
        };
        for &idx in idxs {
            let rm = self.triggered_events.get(idx).unwrap();
            rm.underlying_atomic().fetch_or(events.bits(), SeqCst);
            rm.wake_all();
        }
    }

    /// Mark the `events` as no longer ocurring on `raw_fd`. This will remove the events from each
    /// of the [`Waitable`]s on this `raw_fd`. Depending on the use case,
    /// [`Waitable::mark_events_as_handled`] might be more applicable.
    ///
    /// Explicitly *not* exposed as a public API, but only as a crate-internal.
    pub(crate) fn unmark_events(&self, raw_fd: RawFd, events: Events) {
        let Some(idxs) = self.fd_to_indexes.get(&raw_fd) else {
            return;
        };
        for &idx in idxs {
            self.triggered_events
                .get(idx)
                .unwrap()
                .underlying_atomic()
                .fetch_and(events.complement().bits(), SeqCst);
        }
    }
}

/// A builder for a [`Waitable`] that specifies a set of [`Events`] that can be waited upon for a
/// particular file or socket.
pub struct WaitableBuilder {
    raw_fd: RawFd,
    events: Events,
    spurious_wakeups: SpuriousWakeups,
}

impl WaitableBuilder {
    /// Begin building a waitable for events on a file
    #[must_use]
    pub fn on_file(fd: &OwnedFd) -> Self {
        Self {
            raw_fd: fd.as_raw_fd(),
            events: Events::empty(),
            spurious_wakeups: SpuriousWakeups::Allowed,
        }
    }

    /// Begin building a waitable for events on a socket
    #[must_use]
    pub fn on_socket(fd: &SocketFd) -> Self {
        Self {
            raw_fd: fd.fd.as_raw_fd(),
            events: Events::empty(),
            spurious_wakeups: SpuriousWakeups::Allowed,
        }
    }

    /// Use `events` as the target set
    pub fn with_events(&mut self, events: Events) -> &mut Self {
        self.events = events;
        self
    }

    /// Get the current active set of polled events
    #[must_use]
    pub(crate) fn polled_events(&self) -> Events {
        self.events | Events::ALWAYS_POLLED
    }

    /// Set spurious wake-up control
    pub fn with_spurious_wakeups(&mut self, control: SpuriousWakeups) -> &mut Self {
        self.spurious_wakeups = control;
        self
    }
}

/// A [`register`](EventManager::register)ed interest in waiting that actually allows performing a
/// [`wait`](Self::wait).
pub struct Waitable<'b, Platform: RawMutexProvider> {
    // A reference to the underlying raw-mutex used for communicating the events
    rm: Arc<Platform::RawMutex>,
    // An immutable reference to the builder prevents modification of the choice of events or such
    // until de-registered by dropping.
    builder: &'b WaitableBuilder,
    // An index into the `triggered_events`
    index: Index,
}

impl<Platform: RawMutexProvider> Waitable<'_, Platform> {
    /// Wait for the chosen events to occur, returning which events actually occurred, up to a
    /// specified time-out; spurious wake-ups are always allowed.
    fn wait_with_possible_spurious(
        &self,
        timeout: Option<core::time::Duration>,
    ) -> Result<Events, WaitError> {
        // Clear out anything that isn't part of the events we care about
        self.rm
            .underlying_atomic()
            .fetch_and(self.builder.polled_events().complement().bits(), SeqCst);

        // Now actually wait as necessary
        if let Some(timeout) = timeout {
            match self.rm.block_or_timeout(Events::empty().bits(), timeout) {
                Ok(UnblockedOrTimedOut::Unblocked) | Err(ImmediatelyWokenUp {}) => {
                    Ok(self.builder.polled_events()
                        & Events::from_bits(self.rm.underlying_atomic().load(SeqCst)).unwrap())
                }
                Ok(UnblockedOrTimedOut::TimedOut) => Err(WaitError::TimeOut),
            }
        } else {
            match self.rm.block(Events::empty().bits()) {
                Ok(()) | Err(ImmediatelyWokenUp {}) => Ok(self.builder.polled_events()
                    & Events::from_bits(self.rm.underlying_atomic().load(SeqCst)).unwrap()),
            }
        }
    }

    /// Wait for the chosen events to occur, returning which events actually occurred, up to a
    /// specified time-out; spurious wake-ups are suppressed if builder said so.
    fn wait_with_suppression_if_needed(
        &self,
        timeout: Option<core::time::Duration>,
    ) -> Result<Events, WaitError> {
        loop {
            let events = self.wait_with_possible_spurious(timeout)?;
            if matches!(self.builder.spurious_wakeups, SpuriousWakeups::Allowed)
                || !(events & self.builder.polled_events()).is_empty()
            {
                return Ok(events);
            }
        }
    }

    /// Wait for the chosen events to occur, returning which events actually occurred.
    ///
    /// Note that this function is allowed to get spurious wake-ups if the builder didn't explicitly
    /// set up suppression.
    pub fn wait(&self) -> Result<Events, WaitError> {
        self.wait_with_suppression_if_needed(None)
    }

    /// Wait for the chosen events to occur, timing out after a specified duration.
    ///
    /// Note that this function is allowed to get spurious wake-ups if the builder didn't explicitly
    /// set up suppression.
    pub fn wait_timeout(&self, timeout: core::time::Duration) -> Result<Events, WaitError> {
        self.wait_with_suppression_if_needed(Some(timeout))
    }

    /// Mark the active events as handled. Depending on the use case,
    /// [`EventManager::unmark_events`] might be more applicable.
    ///
    /// Explicitly *not* exposed as a public API, but only as a crate-internal.
    pub(crate) fn mark_events_as_handled(&self) {
        self.rm
            .underlying_atomic()
            .fetch_and(self.builder.polled_events().complement().bits(), SeqCst);
    }
}

/// Whether spurious wake-ups are allowed
pub enum SpuriousWakeups {
    /// Automatically re-wait to prevent spurious wake-ups
    Suppressed,
    /// Allow spurious wake-ups
    Allowed,
}

#[derive(Error, Debug)]
pub enum WaitError {
    #[error("Operation timed out")]
    TimeOut,
}

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    pub struct Events: u32 {
        /// `POLLIN`: There is data to be read.
        const IN    = 0x0001;
        /// `POLLPRI`: There is some exceptional condition on the file descriptor.
        const PRI   = 0x0002;
        /// `POLLOUT`: Writing is now possible, though a write larger than the available space in a socket or pipe will still block.
        const OUT   = 0x0004;
        /// `POLLERR`: Error condition (always returnable).
        const ERR   = 0x0008;
        /// `POLLHUP`: Hang up (always returnable).
        const HUP   = 0x0010;
        /// `POLLNVAL`: Invalid request: fd not open (always returnable).
        const NVAL  = 0x0020;
        /// `POLLRDHUP`: Stream socket peer closed connection, or shut down writing half of connection.
        const RDHUP = 0x2000;

        /// Events that can be returned even if they are not specified
        const ALWAYS_POLLED = Self::ERR.bits() | Self::HUP.bits() | Self::NVAL.bits();

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
