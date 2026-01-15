#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Normal,
    Degraded,
    Failover,
    Recovery,
}

#[derive(Debug)]
pub struct StateMachine {
    state: EngineState,
}

impl StateMachine {
    pub fn new() -> Self {
        Self {
            state: EngineState::Normal,
        }
    }

    pub fn state(&self) -> EngineState {
        self.state
    }

    pub fn set_state(&mut self, state: EngineState) {
        self.state = state;
    }

    pub fn transition(&mut self, latency_ms: Option<u32>, error_rate: Option<f32>) {
        let latency_high = latency_ms.unwrap_or(0) > 120;
        let error_high = error_rate.unwrap_or(0.0) > 0.05;

        self.state = match self.state {
            EngineState::Normal => {
                if latency_high || error_high {
                    EngineState::Degraded
                } else {
                    EngineState::Normal
                }
            }
            EngineState::Degraded => {
                if latency_high || error_high {
                    EngineState::Failover
                } else {
                    EngineState::Recovery
                }
            }
            EngineState::Failover => {
                if latency_high || error_high {
                    EngineState::Failover
                } else {
                    EngineState::Recovery
                }
            }
            EngineState::Recovery => {
                if latency_high || error_high {
                    EngineState::Degraded
                } else {
                    EngineState::Normal
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_to_degraded_on_high_latency() {
        let mut sm = StateMachine::new();
        sm.transition(Some(200), None);
        assert_eq!(sm.state(), EngineState::Degraded);
    }

    #[test]
    fn recovery_to_normal_on_clear_conditions() {
        let mut sm = StateMachine::new();
        sm.set_state(EngineState::Recovery);
        sm.transition(Some(10), Some(0.0));
        assert_eq!(sm.state(), EngineState::Normal);
    }
}
