use eframe::egui;
use eframe::egui::{Color32, RichText};

pub fn start_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([850.0, 550.0])
            .with_resizable(false),
        ..Default::default()
    };

    eframe::run_native(
        "⚠️ RAN ⚠️",
        options,
        Box::new(|cc| {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = Color32::from_rgb(20, 20, 20);           
            cc.egui_ctx.set_visuals(visuals);
            Ok(Box::new(RANApp::default()))
        }),
    )
}

struct RANApp {
    time_left_seconds: f64, // Changed to f64 for smooth countdown
    btc_address: String,
}

impl Default for RANApp {
    fn default() -> Self {
        Self {
            time_left_seconds: 259200.0, // 3 days
            btc_address: "1BvBMSEYstDd396nsNvv2i4r9b61G24GjQ".to_string(),
        }
    }
}

impl eframe::App for RANApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Corrected Timer Logic: Subtract the actual time passed since last frame
        if self.time_left_seconds > 0.0 {
            self.time_left_seconds -= ctx.input(|i| i.stable_dt as f64);
            ctx.request_repaint(); 
        }

        // --- LEFT PANEL ---
        // Modern egui uses a string ID for panels
        egui::SidePanel::left("status_panel")
            .resizable(false)
            .exact_width(280.0)
            .frame(egui::Frame::side_top_panel(&ctx.style()).fill(Color32::from_rgb(140, 0, 0)).inner_margin(20.0))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new("⚠️").size(40.0));
                    ui.label(
                        RichText::new("Oops, your files\nare encrypted!")
                            .color(Color32::WHITE)
                            .size(22.0),
                    );
                    
                    ui.add_space(30.0);
                    ui.separator();
                    ui.add_space(20.0);

                    ui.label(RichText::new("Your files will be lost in:").color(Color32::LIGHT_GRAY).size(14.0));
                    ui.add_space(10.0);

                    let total_secs = self.time_left_seconds as u64;
                    let days = total_secs / 86400;
                    let hours = (total_secs % 86400) / 3600;
                    let minutes = (total_secs % 3600) / 60;
                    let seconds = total_secs % 60;
                    let time_string = format!("{:02}d : {:02}h : {:02}m : {:02}s", days, hours, minutes, seconds);

                    ui.label(
                        RichText::new(time_string)
                            .color(Color32::YELLOW)
                            .size(20.0)
                            .monospace(),
                    );

                    ui.add_space(40.0);
                    ui.separator();
                    ui.add_space(20.0);

                    ui.label(RichText::new("Send Bitcoin to this address:").color(Color32::LIGHT_GRAY).size(13.0));
                    ui.add_space(5.0);
                    
                    ui.add(egui::TextEdit::singleline(&mut self.btc_address).font(egui::FontId::monospace(11.0)));

                    ui.add_space(30.0);
                    
                    let check_btn = egui::Button::new(RichText::new("Check Payment").size(16.0))
                        .fill(Color32::from_rgb(50, 50, 50));
                    
                    if ui.add_sized([200.0, 40.0], check_btn).clicked() {
                        // Dummy action
                    }
                });
            });

        // --- CENTRAL PANEL ---
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading(
                RichText::new("What Happened to My Computer?")
                    .color(Color32::from_rgb(255, 100, 100))
                    .size(24.0),
            );
            ui.add_space(10.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "Your important files are encrypted. Many of your documents, photos, videos, \
                        databases and other files are no longer accessible because they have been \
                        encrypted with a military-grade algorithm. \n\n\
                        Perhaps you are busy looking for a way to recover your files, but do not \
                        waste your time. Nobody can recover your files without our decryption service.",
                    )
                    .size(14.0)
                    .color(Color32::LIGHT_GRAY),
                );

                ui.add_space(20.0);
                ui.heading(
                    RichText::new("Can I Recover My Files?")
                        .color(Color32::from_rgb(255, 100, 100))
                        .size(18.0),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new(
                        "Sure. We guarantee that you can recover all your files safely and easily. \
                        But you do not have enough time. If you want to decrypt all your files, \
                        you need to pay. You only have 3 days to submit the payment. After that, \
                        the price will be doubled. If you don't pay in 7 days, you won't be able \
                        to recover your files forever.",
                    )
                    .size(14.0)
                    .color(Color32::LIGHT_GRAY),
                );
                
                ui.add_space(30.0);
                ui.separator();
                ui.add_space(10.0);
                ui.label(
                    RichText::new("⚠️ This is a simulated UI interface for educational purposes / CTF challenges.")
                        .size(12.0)
                        .color(Color32::GRAY)
                );
            });
        });
    }
}