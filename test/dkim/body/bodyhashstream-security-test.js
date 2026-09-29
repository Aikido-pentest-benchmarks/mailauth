/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const { Readable } = require('node:stream');

let { BodyHashStream } = require('../../../lib/dkim/body');

chai.config.includeStack = true;

describe('DKIM BodyHashStream Security Tests', () => {
    describe('Resource exhaustion prevention', () => {
        it('Should reject excessive retained state in simple canonicalization', done => {
            // Test that BodyHashStream properly enforces limits for simple canonicalization
            const stream = new BodyHashStream('simple/simple');
            
            let errorCaught = false;
            stream.on('error', err => {
                errorCaught = true;
                expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                done();
            });
            
            stream.on('finish', () => {
                if (!errorCaught) {
                    done(new Error('Expected error was not thrown'));
                }
            });
            
            // Write initial content to establish remainder state
            stream.write(Buffer.from('a\r'));
            
            // Try to exceed the limit with bare CR bytes
            const crChunk = Buffer.alloc(10000, 0x0d);
            for (let i = 0; i < 10; i++) {
                try {
                    stream.write(crChunk);
                } catch (err) {
                    errorCaught = true;
                    expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                    expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                    done();
                    return;
                }
            }
            
            stream.end();
        });

        it('Should reject excessive retained state in relaxed canonicalization', done => {
            // Test that BodyHashStream properly enforces limits for relaxed canonicalization
            const stream = new BodyHashStream('relaxed/relaxed');
            
            let errorCaught = false;
            stream.on('error', err => {
                errorCaught = true;
                expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                done();
            });
            
            stream.on('finish', () => {
                if (!errorCaught) {
                    done(new Error('Expected error was not thrown'));
                }
            });
            
            // Try to exceed the limit with a large chunk without line endings
            const largeChunk = Buffer.alloc(70000, 0x61); // 70KB of 'a' bytes
            try {
                stream.write(largeChunk);
            } catch (err) {
                errorCaught = true;
                expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                done();
                return;
            }
            
            stream.end();
        });

        it('Should handle legitimate streaming data without errors', done => {
            // Verify that normal streaming usage works correctly
            const stream = new BodyHashStream('simple/simple');
            
            stream.on('error', err => {
                done(err);
            });
            
            stream.on('hash', hash => {
                expect(hash).to.be.a('string');
                done();
            });
            
            // Write normal email body content
            stream.write(Buffer.from('Subject: Test\r\n'));
            stream.write(Buffer.from('\r\n'));
            stream.write(Buffer.from('This is the body.\r\n'));
            stream.write(Buffer.from('Line 2\r\n'));
            stream.end();
        });

        it('Should prevent attack via piped readable stream with simple canon', done => {
            // Test the attack scenario where malicious data is piped through
            const stream = new BodyHashStream('simple/simple');
            
            let errorCaught = false;
            stream.on('error', err => {
                errorCaught = true;
                expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                done();
            });
            
            stream.on('finish', () => {
                if (!errorCaught) {
                    done(new Error('Expected error was not thrown'));
                }
            });
            
            // Create a readable stream that emits malicious data
            const maliciousSource = new Readable({
                read() {
                    // First establish remainder state
                    this.push(Buffer.from('a\r'));
                    
                    // Then send many chunks of bare CR bytes
                    for (let i = 0; i < 10; i++) {
                        this.push(Buffer.alloc(10000, 0x0d));
                    }
                    
                    this.push(null);
                }
            });
            
            maliciousSource.pipe(stream);
        });

        it('Should prevent attack via piped readable stream with relaxed canon', done => {
            // Test the attack scenario where malicious data is piped through
            const stream = new BodyHashStream('relaxed/relaxed');
            
            let errorCaught = false;
            stream.on('error', err => {
                errorCaught = true;
                expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                done();
            });
            
            stream.on('finish', () => {
                if (!errorCaught) {
                    done(new Error('Expected error was not thrown'));
                }
            });
            
            // Create a readable stream that emits malicious data
            const maliciousSource = new Readable({
                read() {
                    // Send a large chunk without line endings
                    this.push(Buffer.alloc(70000, 0x61));
                    this.push(null);
                }
            });
            
            maliciousSource.pipe(stream);
        });

        it('Should track byteLength correctly even when rejecting data', done => {
            // Verify that byteLength tracking works correctly
            const stream = new BodyHashStream('simple/simple');
            
            let errorCaught = false;
            stream.on('error', _err => {
                errorCaught = true;
                // byteLength should reflect data written before error
                expect(stream.byteLength).to.be.greaterThan(0);
                done();
            });
            
            stream.on('finish', () => {
                if (!errorCaught) {
                    done(new Error('Expected error was not thrown'));
                }
            });
            
            stream.write(Buffer.from('a\r'));
            
            const crChunk = Buffer.alloc(10000, 0x0d);
            for (let i = 0; i < 10; i++) {
                try {
                    stream.write(crChunk);
                } catch (err) {
                    errorCaught = true;
                    expect(stream.byteLength).to.be.greaterThan(0);
                    done();
                    return;
                }
            }
            
            stream.end();
        });

        it('Should work correctly with l= parameter and enforce limit', done => {
            // Verify that l= parameter works but doesn't bypass security checks
            const stream = new BodyHashStream('simple/simple', 'rsa-sha256', 1000);
            
            let errorCaught = false;
            stream.on('error', err => {
                errorCaught = true;
                expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                done();
            });
            
            stream.on('finish', () => {
                if (!errorCaught) {
                    done(new Error('Expected error was not thrown'));
                }
            });
            
            stream.write(Buffer.from('a\r'));
            
            const crChunk = Buffer.alloc(10000, 0x0d);
            for (let i = 0; i < 10; i++) {
                try {
                    stream.write(crChunk);
                } catch (err) {
                    errorCaught = true;
                    expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
                    done();
                    return;
                }
            }
            
            stream.end();
        });
    });
});
