use std::cell::RefCell;

use aya::maps::{MapData, RingBuf};
use aya::programs::RawTracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use iced::futures::executor;
use iced::widget::{Column, Scrollable, Text};
use iced::{Application, Command, Element, Length, Theme};
use iced_test_aya_common::Data;
use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/iced-test-aya"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/iced-test-aya"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut RawTracePoint = bpf.program_mut("iced_test_aya").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;

    let events = RingBuf::try_from(bpf.take_map("EVENTS").unwrap()).unwrap();
    let poll = AsyncFd::new(events).unwrap();

    tokio::task::block_in_place(|| {
        State::run(iced::Settings {
            flags: Flag { poll: Some(poll) },
            ..Default::default()
        })
        .unwrap();
    });

    Ok(())
}

struct State {
    poll: RefCell<Option<AsyncFd<RingBuf<MapData>>>>,
    n_events: usize,
    events: Vec<Data>,
}

#[derive(Default)]
struct Flag {
    poll: Option<AsyncFd<RingBuf<MapData>>>,
}

#[derive(Debug)]
enum Message {
    Tick,
    Events(Vec<Data>),
}

impl Application for State {
    type Executor = executor::ThreadPool;

    type Message = self::Message;

    type Theme = Theme;

    type Flags = Flag;

    fn subscription(&self) -> iced::Subscription<Self::Message> {
        iced::subscription::unfold("ebpf event", self.poll.take(), move |poll| async move {
            let Some(mut poll) = poll else {
                return (Message::Tick, poll);
            };
            let mut events = Vec::new();

            let mut guard = poll.readable_mut().await.unwrap();
            let inner = guard.get_inner_mut();
            while let Some(ref data) = inner.next() {
                let [data]: &[Data] = unsafe { data.align_to() }.1 else {
                    continue;
                };

                events.push(data.clone());
                info!("{:?}", data);
            }
            guard.clear_ready();

            (Message::Events(events), Some(poll))
        })
    }

    fn new(flags: Self::Flags) -> (Self, iced::Command<Self::Message>) {
        (
            Self {
                events: Vec::new(),
                n_events: 0,
                poll: RefCell::new(flags.poll),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        "Aya and iced".to_string()
    }

    fn update(&mut self, message: Self::Message) -> iced::Command<Self::Message> {
        match message {
            Message::Tick => Command::none(),
            Message::Events(e) => {
                self.n_events += e.len();
                self.events.extend(e);
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let content = Column::new()
            .align_items(iced::Alignment::Start)
            .width(Length::Fill)
            .height(Length::Fill)
            .push(Text::new(format!("Events: {:?}", self.n_events)))
            .push(Scrollable::new(
                Column::new()
                    .width(Length::Fill)
                    .extend(
                        self.events
                            .iter()
                            .rev()
                            .map(|e| Text::new(format!("Event: {e}")))
                            .map(|t| t.into()),
                    )
                    .width(Length::Fill),
            ));

        content.into()
    }

    fn theme(&self) -> Self::Theme {
        Self::Theme::default()
    }

    fn style(&self) -> <Self::Theme as iced::application::StyleSheet>::Style {
        <Self::Theme as iced::application::StyleSheet>::Style::default()
    }

    fn scale_factor(&self) -> f64 {
        1.0
    }

    //     fn run(settings: iced::Settings<Self::Flags>) -> iced::Result
    //     where
    //         Self: 'static,
    //     {
    //         #[allow(clippy::needless_update)]
    //         let renderer_settings = iced::renderer::Settings {
    //             default_font: settings.default_font,
    //             default_text_size: settings.default_text_size,
    //             antialiasing: if settings.antialiasing {
    //                 Some(iced::graphics::Antialiasing::MSAAx4)
    //             } else {
    //                 None
    //             },
    //             ..iced::renderer::Settings::default()
    //         };

    //         Ok(iced::shell::application::run::<
    //             Instance<Self>,
    //             Self::Executor,
    //             iced::renderer::Compositor,
    //         >(settings.into(), renderer_settings)?)
    //     }
}
