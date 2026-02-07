import { FlatDropCore } from '../core/FlatDropCore';

@Entry
@Component
struct Index {
  @State message: string = 'FlatDrop Core Status: ...';
  @State initialized: boolean = false;

  async aboutToAppear() {
    try {
      // Start the core with default config
      const nodeId = await FlatDropCore.start({});
      this.message = `Core Active\nNode ID: ${nodeId}`;
      this.initialized = true;
    } catch (e) {
      this.message = `Error starting core: ${e.message}`;
    }
  }

  build() {
    Stack() {
      // Dynamic Background
      Row()
        .width('100%')
        .height('100%')
        .linearGradient({
          angle: 135,
          colors: [[0x0f172a, 0.0], [0x1e293b, 1.0]]
        })

      // Content
      Column() {
        // Status Card with Glass Effect
        Column() {
          Text('FlatDrop')
            .fontSize(36)
            .fontWeight(FontWeight.Bold)
            .fontColor(Color.White)
            .margin({ bottom: 20 })
          
          Text(this.message)
            .fontSize(16)
            .fontColor(Color.White)
            .textAlign(TextAlign.Center)
            .opacity(0.8)
            .margin({ bottom: 20 })
          
          Button(this.initialized ? 'Stop Core' : 'Retry Start')
            .onClick(() => {
              if (this.initialized) {
                FlatDropCore.stop();
                this.initialized = false;
                this.message = 'Core Stopped';
              } else {
                this.aboutToAppear();
              }
            })
            .backgroundColor(0x3b82f6)
            .fontColor(Color.White)
            .borderRadius(12)
            .width(160)
            .height(48)
        }
        .width('90%')
        .padding(30)
        .backgroundColor('rgba(255, 255, 255, 0.1)') // Translucent white
        .backdropBlur(20) // Glass blur effect
        .borderRadius(24)
        .shadow({ radius: 20, color: 'rgba(0, 0, 0, 0.2)', offsetX: 0, offsetY: 10 })
        .border({ width: 1, color: 'rgba(255, 255, 255, 0.2)' }) // Glass border
      }
      .width('100%')
      .justifyContent(FlexAlign.Center)
    }
    .height('100%')
  }
}
