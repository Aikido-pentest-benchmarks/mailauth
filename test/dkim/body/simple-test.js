/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;
const crypto = require('node:crypto');

let fs = require('node:fs').promises;
let { SimpleHash } = require('../../../lib/dkim/body/simple');

chai.config.includeStack = true;

const getBody = message => {
    message = message.toString('binary');
    let match = message.match(/\r?\n\r?\n/);
    if (match) {
        message = message.substr(match.index + match[0].length);
    }
    return Buffer.from(message.replace(/\r?\n/g, '\r\n'), 'binary');
};

describe('DKIM SimpleBody Tests', () => {
    it('Should calculate sha256 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=');
    });

    it('Should calculate sha1 body hash for an empty message', async () => {
        const message = Buffer.from('\r\n\r\n\n\r\n\r\n');

        let s = new SimpleHash('rsa-sha1');
        s.update(message);

        expect(s.digest('base64')).to.equal('uoq1oCgLlTqpdDX/iUbLy7J1Wic=');
    });

    it('Should calculate body hash byte by byte', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256');
        for (let i = 0; i < message.length; i++) {
            s.update(Buffer.from([message[i]]));
        }

        expect(s.digest('base64')).to.equal('GjyEkbey2OupCW5AKJv4dzTPsPHSaZjRDMqUSmhpTyQ=');
    });

    it('Should calculate body hash all at once', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256');
        s.update(message);

        expect(s.digest('base64')).to.equal('GjyEkbey2OupCW5AKJv4dzTPsPHSaZjRDMqUSmhpTyQ=');
    });

    it('Should calculate body hash with l=0', async () => {
        let message = await fs.readFile(__dirname + '/../../fixtures/message1.eml');
        message = getBody(message);

        let s = new SimpleHash('rsa-sha256', 0);
        s.update(message);

        expect(s.digest('base64')).to.equal('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });

    it('Should calculate body hash with l=20', async () => {
        let s = new SimpleHash('rsa-sha256', 20);
        s.update(Buffer.from('tere tere\r\n \r\nvana kere\r\n\r\n'));

        expect(s.digest('base64')).to.equal(
            crypto
                .createHash('sha256')
                .update(Buffer.from(['tere tere\r\n', ' \r\n', 'vana k'].join('')))
                .digest('base64')
        );
    });

    describe('Canonicalization edge cases', () => {
        // reference implementation of RFC 6376 section 3.4.3, see the reasoning on
        // SimpleHash.digest in lib/dkim/body/simple.js
        const reference = body => {
            const buf = Buffer.from(body, 'binary');
            let end = buf.length;
            while (end > 0 && buf[end - 1] === 0x0a) {
                end -= 1;
                if (end > 0 && buf[end - 1] === 0x0d) {
                    end -= 1;
                }
            }
            return crypto
                .createHash('sha256')
                .update(Buffer.concat([buf.subarray(0, end), Buffer.from('\r\n')]))
                .digest('base64');
        };

        const hashChunks = chunks => {
            const s = new SimpleHash('rsa-sha256');
            for (const chunk of chunks) {
                s.update(Buffer.from(chunk, 'binary'));
            }
            return s.digest('base64');
        };

        for (const body of [
            '',
            'abc',
            'abc\r\n',
            'abc\r\n\r\n\r\n',
            // a lone <CR> is content, not a line ending
            'abc\r',
            'abc\r\r\n',
            'abc\r\r',
            'a\r\n\r',
            '\r',
            '\r\r\n',
            'x\r\ny\r',
            'a\rb\r\n'
        ]) {
            it(`Should canonicalize ${JSON.stringify(body)} as RFC 6376 section 3.4.3 does`, () => {
                expect(hashChunks([body])).to.equal(reference(body));
            });
        }

        it('Should count line endings at the end of the body instead of buffering them', () => {
            // the message parser hands over one small buffer per line, and each of those
            // pins the pool it came from, so a body of bare line breaks used to be
            // retained about two hundred times over
            const s = new SimpleHash('rsa-sha256');
            for (let i = 0; i < 5000; i++) {
                s.update(Buffer.from('\r\n'));
            }
            expect(s.pendingLineBreaks).to.equal(5000);
            expect(s.remainder).to.have.lengthOf(0);
            expect(s.digest('base64')).to.equal(reference(''));
        });

        it('Should keep held back bytes that are not whole CRLF pairs', () => {
            // a lone <CR> cannot be stood in for by the counter, so the exact bytes are
            // kept. Pairs counted before them stay counted, they are emitted first anyway
            const s = new SimpleHash('rsa-sha256');
            s.update(Buffer.from('a'));
            s.update(Buffer.from('\r\n'));
            s.update(Buffer.from('\r'));
            s.update(Buffer.from('b'));
            expect(s.digest('base64')).to.equal(reference('a\r\n\rb'));
        });

        it('Should give the same hash whatever the chunk boundaries are', () => {
            for (const body of ['abc\r', 'a\r\n\r', 'abc\r\r\n', 'x\r\ny\r\r\n\r\n', 'a\rb\r\nc']) {
                const refHash = reference(body);
                for (let i = 1; i < body.length; i++) {
                    expect(hashChunks([body.slice(0, i), body.slice(i)])).to.equal(refHash, `hash mismatch for ${JSON.stringify(body)} at split ${i}`);
                }
                // one byte at a time
                expect(hashChunks(body.split(''))).to.equal(refHash, `hash mismatch for ${JSON.stringify(body)} split bytewise`);
            }
        });

        it('Should reject excessive retained canonicalization state', () => {
            // Prevent resource exhaustion from unbounded growth of remainder array.
            // An attacker could send many chunks of bare CR bytes to grow the remainder
            const s = new SimpleHash('rsa-sha256');
            s.update(Buffer.from('a'));
            // First chunk with trailing CR is held back
            s.update(Buffer.from('\r'));
            expect(s.remainder).to.have.lengthOf(1);

            // Try to exceed the limit by adding many chunks of bare CR bytes
            const crChunk = Buffer.alloc(10000, 0x0d); // 10KB of CR bytes
            expect(() => {
                // This should eventually throw when remainder exceeds maxRemainderSize (64KB)
                for (let i = 0; i < 10; i++) {
                    s.update(crChunk);
                }
            }).to.throw('Maximum retained canonicalization state exceeded');
        });

        it('Should reject single large chunk exceeding remainder limit', () => {
            // Test that a single chunk with trailing CR/LF data exceeding the limit is rejected
            const s = new SimpleHash('rsa-sha256');
            s.update(Buffer.from('content\r\n'));
            
            // Create a chunk that's larger than maxRemainderSize (64KB) with trailing CRs
            const largeChunk = Buffer.alloc(70000, 0x0d); // 70KB of CR bytes
            expect(() => {
                s.update(largeChunk);
            }).to.throw('Maximum retained canonicalization state exceeded');
        });

        it('Should throw error with correct error code', () => {
            // Verify the error has the expected code for monitoring/handling
            const s = new SimpleHash('rsa-sha256');
            s.update(Buffer.from('a\r'));
            
            const crChunk = Buffer.alloc(10000, 0x0d);
            try {
                for (let i = 0; i < 10; i++) {
                    s.update(crChunk);
                }
                expect.fail('Should have thrown an error');
            } catch (err) {
                expect(err.code).to.equal('DKIM_BODY_CANON_LIMIT');
                expect(err.message).to.equal('Maximum retained canonicalization state exceeded');
            }
        });

        it('Should allow legitimate trailing line endings within limit', () => {
            // Verify that normal usage with reasonable trailing data still works
            const s = new SimpleHash('rsa-sha256');
            
            // Add content with various trailing patterns that stay within limit
            s.update(Buffer.from('line1\r\n'));
            s.update(Buffer.from('line2\r'));
            s.update(Buffer.from('\nline3\r\n'));
            
            // Should not throw
            const hash = s.digest('base64');
            expect(hash).to.be.a('string');
        });

        it('Should track remainderSize correctly across multiple updates', () => {
            // Verify that remainderSize tracking is accurate
            const s = new SimpleHash('rsa-sha256');
            
            // Add content that creates remainder
            s.update(Buffer.from('a'));
            s.update(Buffer.from('\r'));
            expect(s.remainderSize).to.equal(1);
            
            // Add more trailing data
            s.update(Buffer.alloc(100, 0x0d));
            expect(s.remainderSize).to.equal(101);
            
            // Drain by adding non-trailing content
            s.update(Buffer.from('b'));
            expect(s.remainderSize).to.equal(0);
        });

        it('Should prevent resource exhaustion via cross-chunk line-ending attack', () => {
            // Reproduce the specific attack: chunks with bare CR that leave remainder nonempty,
            // followed by CRLF-only suffixes that bypass the counter
            const s = new SimpleHash('rsa-sha256');
            
            // Initial content to establish state
            s.update(Buffer.from('content'));
            
            // First chunk with trailing CR establishes nonempty remainder
            s.update(Buffer.from('\r'));
            expect(s.remainder.length).to.be.greaterThan(0);
            
            // Now send many chunks that are CRLF-only suffixes
            // These would bypass pendingLineBreaks counter and grow remainder
            const crlfChunk = Buffer.alloc(8000, 0x0d); // 8KB of CR bytes
            expect(() => {
                for (let i = 0; i < 10; i++) {
                    s.update(crlfChunk);
                }
            }).to.throw('Maximum retained canonicalization state exceeded');
        });

        it('Should handle l= parameter without bypassing remainder limit', () => {
            // Verify that the l= body-length parameter doesn't bypass the security check
            const s = new SimpleHash('rsa-sha256', 1000); // l=1000
            
            s.update(Buffer.from('a\r'));
            
            // Try to exceed remainder limit even with l= set
            const crChunk = Buffer.alloc(10000, 0x0d);
            expect(() => {
                for (let i = 0; i < 10; i++) {
                    s.update(crChunk);
                }
            }).to.throw('Maximum retained canonicalization state exceeded');
        });
    });
});
