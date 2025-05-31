const puppeteer = require('puppeteer');

async function testFrontend() {
    const browser = await puppeteer.launch({ 
        headless: false,
        devtools: true 
    });
    
    const page = await browser.newPage();
    
    page.on('console', msg => {
        console.log(`[BROWSER] ${msg.type()}: ${msg.text()}`);
    });
    
    page.on('pageerror', error => {
        console.log(`[PAGE ERROR] ${error.message}`);
    });
    
    try {
        await page.goto('http://localhost:8080', { waitUntil: 'networkidle0' });
        
        console.log('Page loaded, waiting for WASM...');
        await page.waitForFunction(() => document.querySelector('#statusMessage')?.textContent?.includes('Ready'));
        
        console.log('Generating keys...');
        await page.click('#generateKeysBtn');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        console.log('Typing message...');
        await page.type('#messageToSign', 'Hello MAYO test');
        
        console.log('Attempting to sign...');
        await page.click('#signMessageBtn');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const signature = await page.$eval('#signature', el => el.value);
        console.log('Signature:', signature ? 'SUCCESS' : 'FAILED');
        
        if (signature) {
            console.log('Attempting to verify...');
            await page.click('#verifySignatureBtn');
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            const status = await page.$eval('#statusMessage', el => el.textContent);
            console.log('Verification status:', status);
        }
        
    } catch (error) {
        console.error('Test error:', error);
    }
    
    console.log('Test complete - keeping browser open');
}

testFrontend().catch(console.error); 