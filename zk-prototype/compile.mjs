import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
// The pinned compiler wrapper mixes Windows separators in its source map and
// treats backslashes as regex escapes. Normalize paths, without changing Noir.
if (process.platform === 'win32') {
    const require = createRequire(import.meta.url);
    const path = require.resolve('@noir-lang/noir_wasm');
    let source = await readFile(path, 'utf8');
    source = source.replaceAll('const entrypoint = this.#package.getEntryPointPath();',
        'const entrypoint = this.#package.getEntryPointPath().replaceAll("\\\\", "/");');
    source = source.replaceAll('this.#sourceMap.add_source_code(sourceFile.path, sourceFile.source);',
        'this.#sourceMap.add_source_code(sourceFile.path.replaceAll("\\\\", "/"), sourceFile.source);');
    source = source.replace('const suffix = file.replace(new RegExp(`.*${this.#srcPath}`), \'\');',
        'const suffix = file.slice(this.#srcPath.length).replaceAll("\\\\", "/");');
    await writeFile(path, source);
}
const { compile_program, createFileManager } = await import('@noir-lang/noir_wasm');
const requestBridge = process.argv[2] === '--request';
const output = new URL(requestBridge ? '../request-proof/artifacts/' : './artifacts/', import.meta.url);
const folder = fileURLToPath(new URL(requestBridge ? '../request-proof/circuit/' : './circuit/', import.meta.url));
const start = performance.now();
let compiled;
try {
    compiled = await compile_program(createFileManager(folder), undefined,
        () => {}, (message) => { if (message.startsWith('Adding source sha256')) console.log(message); });
} catch (error) {
    const diagnostics = error.cause?.diagnostics ?? error.diagnostics ?? [];
    console.log(JSON.stringify({ failed: true, message:String(error.message).slice(0,3000), diagnostics: diagnostics.slice(0, 12).map(d => ({message:d.message,file:d.file})), count:diagnostics.length }));
    process.exit(1);
}
const { program, warnings } = compiled;
await mkdir(output, { recursive: true });
// Portable public artifact: omit local paths and debug/source maps.
const portable={noir_version:program.noir_version,abi:program.abi,bytecode:program.bytecode};
await writeFile(new URL('circuit.json', output), JSON.stringify(portable));
console.log(JSON.stringify({ compiled: true, seconds: (performance.now() - start) / 1000,
    warnings: warnings?.length, parameters: program.abi.parameters.map(p => ({name:p.name, visibility:p.visibility})) }));
