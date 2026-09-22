const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');

const srcDir = path.join(__dirname, '..', 'frontend', 'src_js');
const distDir = path.join(__dirname, '..', 'frontend', 'js');

const files = ['security.js', 'pdx_shield.js', 'auth.js', 'app.js', 'admin.js'];

const obfuscatorOptions = {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.75,
    deadCodeInjection: false,
    debugProtection: true,
    debugProtectionInterval: 2000,
    disableConsoleOutput: false,
    identifierNamesGenerator: 'hexadecimal',
    log: false,
    numbersToExpressions: true,
    renameGlobals: false,
    selfDefending: true,
    simplify: true,
    splitStrings: true,
    splitStringsChunkLength: 8,
    stringArray: true,
    stringArrayCallsTransform: true,
    stringArrayCallsTransformThreshold: 0.75,
    stringArrayEncoding: ['base64', 'rc4'],
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 2,
    stringArrayWrappersChainedCalls: true,
    stringArrayWrappersParametersMaxCount: 4,
    stringArrayWrappersType: 'function',
    stringArrayThreshold: 0.8,
    target: 'browser'
};

if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
}

files.forEach(file => {
    const srcPath = path.join(srcDir, file);
    if (!fs.existsSync(srcPath)) {
        return;
    }
    const code = fs.readFileSync(srcPath, 'utf8');
    const obfuscationResult = JavaScriptObfuscator.obfuscate(code, obfuscatorOptions);
    const destPath = path.join(distDir, file);
    fs.writeFileSync(destPath, obfuscationResult.getObfuscatedCode(), 'utf8');
    console.log(`Obfuscated: ${file} -> ${(fs.statSync(destPath).size / 1024).toFixed(1)} KB`);
});
