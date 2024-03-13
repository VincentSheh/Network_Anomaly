const puppeteer = require('puppeteer');

(async () => {
  try {
    let browser = await puppeteer.launch({
      headless: false,
      args: [
        `--use-fake-device-for-media-stream`,
        `--use-fake-ui-for-media-stream`,
        `--no-sandbox`,
        `--use-file-for-fake-video-capture=/your/full/path/to/the/video.mjpeg`,
      ],
    });
    const page = await browser.newPage();

    await page.goto(
      `https://www.youtube.com/watch?v=byfyRgISriA&t=950s`,
    );
    
    // Won't disconnect it, since we want to see it happening
  } catch (err) {
    console.error(err);
  }
})();