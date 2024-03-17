const puppeteer = require('puppeteer');
// Array of location, then select the location randomly
function getRandomPlace(placesArray) {
  const randomIndex = Math.floor(Math.random() * placesArray.length);
  return placesArray[randomIndex];
}
function getRandomInt(max) {
  return Math.floor(Math.random() * max);
}
const delay = (ms) => new Promise(res => setTimeout(res, ms));

(async ()=> {
  // Launch a browser instance
    while (true){
      try{
        const places = ["Taipei 101", "Tamsui", "Ximen", "Taipei Main Station"]
        let browser = await puppeteer.launch({
          headless: true,
          args: [
            `--no-sandbox`,
            '--disable-setuid-sandbox',
          ],
        });  // Open a new page
        const page = await browser.newPage();
        
        // Go to a webpage that contains a Google Map.
        // Replace 'your_website_with_map.com' with the actual URL
        // await page.goto('http://localhost:3000/map'); 
        await page.goto('http://parkingtracker.com/map');    
        console.log("Opened New browser")
        for (let i=0;i<getRandomInt(25); i++){
          const searchSelector = '.pac-target-input'; // Using one of the provided classes
          const place = getRandomPlace(places)
          console.log("Finding Route to : ", place)
          await page.waitForSelector(searchSelector);
          await page.type(searchSelector, place);
      
          const goButtonSelector = 'button.px-2.text-white.bg-black.border-l.rounded';
          await page.waitForSelector(goButtonSelector); // Wait for the button to be ready
          await page.click(goButtonSelector); // Click the button
          await delay(getRandomInt(10000))
          await page.evaluate((selector) => {
            document.querySelector(selector).value = ''; // Clear the input field
          }, searchSelector);        
        }
        page.close()
      }catch (err) {
        console.error(err);
      }


  } 
})();

