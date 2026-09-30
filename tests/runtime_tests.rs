#[cfg(test_harness = "logger")]
mod logger {
    include!("../builds/logger-tests/definitions.rs");

    use std::cell::RefCell;
    use std::collections::VecDeque;

    #[test]
    fn firmware_console_requires_bsp_and_enabled_interrupts() {
        for bsp in [false, true] {
            for interrupts in [false, true] {
                let rflags = 0x46 | (u64::from(interrupts) << 9);
                let apic_base = 0xfee0_0800 | (u64::from(bsp) << 8);
                assert_eq!(firmware_calls_allowed(rflags, apic_base), bsp && interrupts);
            }
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum UartMode {
        FloatingBus,
        ZeroBus,
        BrokenScratch,
        BrokenLoopback,
        StoppedClock,
        Present,
    }

    struct Uart {
        mode: UartMode,
        registers: [u8; 8],
        divisor: [u8; 2],
        received: VecDeque<u8>,
        external_transmit: Vec<u8>,
        reads: usize,
        writes: Vec<(u16, u8)>,
    }

    impl Uart {
        fn new(mode: UartMode) -> Self {
            Self {
                mode,
                registers: [0, 5, 0, 0x83, 8, TRANSMIT_EMPTY | 0x40, 0, 0x27],
                divisor: [0x34, 0x12],
                received: VecDeque::new(),
                external_transmit: Vec::new(),
                reads: 0,
                writes: Vec::new(),
            }
        }

        fn read(&mut self, port: u16) -> u8 {
            self.reads += 1;
            if self.mode == UartMode::FloatingBus {
                return 0xff;
            }
            if self.mode == UartMode::ZeroBus {
                return 0;
            }
            let index = usize::from(port - COM1);
            if index < 2 && self.registers[3] & 0x80 != 0 {
                return self.divisor[index];
            }
            if index == 0 {
                return self.received.pop_front().unwrap_or(0);
            }
            if index == 5 {
                return self.registers[5] | u8::from(!self.received.is_empty());
            }
            self.registers[index]
        }

        fn write(&mut self, port: u16, value: u8) {
            self.writes.push((port, value));
            if matches!(self.mode, UartMode::FloatingBus | UartMode::ZeroBus) {
                return;
            }
            let index = usize::from(port - COM1);
            if index < 2 && self.registers[3] & 0x80 != 0 {
                self.divisor[index] = value;
            } else if index == 0 {
                if self.registers[4] & 0x10 == 0 {
                    self.external_transmit.push(value);
                } else if self.mode != UartMode::StoppedClock {
                    self.received
                        .push_back(if self.mode == UartMode::BrokenLoopback {
                            value ^ 1
                        } else {
                            value
                        });
                }
            } else if index != 7 || self.mode != UartMode::BrokenScratch {
                self.registers[index] = value;
            }
        }
    }

    fn probe(uart: &RefCell<Uart>) -> bool {
        probe_com1(
            |port| uart.borrow_mut().read(port),
            |port, value| uart.borrow_mut().write(port, value),
        )
    }

    #[test]
    fn disabled_logger_never_probes_ports() {
        assert_eq!(
            select_backend(false, || panic!("unexpected UART access")),
            LogBackend::Disabled
        );
    }

    #[test]
    fn enabled_logger_keeps_visible_output_with_or_without_a_uart() {
        for uart_available in [false, true] {
            let sinks = select_backend(true, || uart_available) as u8;
            assert_ne!(sinks & FRAMEBUFFER_SINK, 0);
            assert_eq!(sinks & SERIAL_SINK != 0, uart_available);
        }
    }

    #[test]
    fn configuration_toggle_preserves_detected_serial_port() {
        SERIAL_PRESENT.store(true, Ordering::Release);
        set_enabled(true);
        assert_eq!(backend(), LogBackend::SerialAndFramebuffer);
        set_enabled(false);
        assert_eq!(backend(), LogBackend::Disabled);
        set_enabled(true);
        assert_eq!(backend(), LogBackend::SerialAndFramebuffer);
        SERIAL_PRESENT.store(false, Ordering::Release);
        set_enabled(true);
        assert_eq!(backend(), LogBackend::Framebuffer);
        set_enabled(false);
    }

    #[test]
    fn absent_ports_select_framebuffer_without_initializing_a_uart() {
        for mode in [
            UartMode::FloatingBus,
            UartMode::ZeroBus,
            UartMode::BrokenScratch,
        ] {
            let uart = RefCell::new(Uart::new(mode));
            assert_eq!(
                select_backend(true, || probe(&uart)),
                LogBackend::Framebuffer
            );
            assert!(
                uart.borrow()
                    .writes
                    .iter()
                    .all(|&(port, _)| port == COM1 + 7)
            );
        }
    }

    #[test]
    fn valid_uart_selects_serial_and_keeps_probe_bytes_internal() {
        let uart = RefCell::new(Uart::new(UartMode::Present));
        uart.borrow_mut().received.extend([0x11, 0x22]);
        assert_eq!(
            select_backend(true, || probe(&uart)),
            LogBackend::SerialAndFramebuffer
        );
        let uart = uart.borrow();
        assert_eq!(uart.registers[3], 3);
        assert_eq!(uart.registers[4], 0x0b);
        assert_eq!(uart.registers[7], 0x27);
        assert_eq!(uart.divisor, [1, 0]);
        assert!(uart.external_transmit.is_empty());
        assert!(uart.received.is_empty());
    }

    #[test]
    fn failed_loopback_restores_uart_configuration() {
        for mode in [UartMode::BrokenLoopback, UartMode::StoppedClock] {
            let uart = RefCell::new(Uart::new(mode));
            let original = uart.borrow().registers;
            assert_eq!(
                select_backend(true, || probe(&uart)),
                LogBackend::Framebuffer
            );
            let uart = uart.borrow();
            assert_eq!(uart.registers, original);
            assert_eq!(uart.divisor, [0x34, 0x12]);
            assert!(uart.reads <= TX_WAIT_LIMIT + 80);
            assert!(uart.external_transmit.is_empty());
        }
    }
}
