import React, { useState } from 'react';
import { Upload, AlertCircle, Info, FileText } from 'lucide-react';

const BountyAnalyzer = () => {
  const [aCt, setACt] = useState(null);
  const [bCt, setBCt] = useState(null);
  const [pkBin, setPkBin] = useState(null);
  const [analysis, setAnalysis] = useState(null);

  const readFileAsArrayBuffer = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(new Uint8Array(e.target.result));
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  };

  const analyzeFiles = async () => {
    if (!aCt || !bCt) {
      alert('Please upload both a.ct and b.ct files');
      return;
    }

    try {
      const aData = await readFileAsArrayBuffer(aCt);
      const bData = await readFileAsArrayBuffer(bCt);
      let pkData = null;
      if (pkBin) {
        pkData = await readFileAsArrayBuffer(pkBin);
      }

      const results = {
        aCt: analyzeBuffer(aData, 'a.ct'),
        bCt: analyzeBuffer(bData, 'b.ct'),
        pk: pkData ? analyzeBuffer(pkData, 'pk.bin') : null,
        comparison: compareBuffers(aData, bData),
        attacks: suggestAttacks(aData, bData)
      };

      setAnalysis(results);
    } catch (error) {
      console.error('Analysis error:', error);
      alert('Error analyzing files: ' + error.message);
    }
  };

  const analyzeBuffer = (data, name) => {
    const result = {
      name,
      size: data.length,
      entropy: calculateEntropy(data),
      patterns: findPatterns(data),
      interpretations: {}
    };

    // Try different interpretations
    result.interpretations.int16 = parseAsInt16(data);
    result.interpretations.int32 = parseAsInt32(data);
    result.interpretations.int64 = parseAsInt64(data);
    result.interpretations.hex = Array.from(data.slice(0, 64))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');

    return result;
  };

  const calculateEntropy = (data) => {
    const freq = new Array(256).fill(0);
    data.forEach(byte => freq[byte]++);
    
    let entropy = 0;
    const len = data.length;
    freq.forEach(count => {
      if (count > 0) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
    });
    
    return entropy.toFixed(4);
  };

  const findPatterns = (data) => {
    const patterns = {
      zeros: 0,
      ones: 0,
      repeated: []
    };

    let currentByte = data[0];
    let count = 1;

    for (let i = 1; i < Math.min(data.length, 10000); i++) {
      if (data[i] === 0) patterns.zeros++;
      if (data[i] === 255) patterns.ones++;

      if (data[i] === currentByte) {
        count++;
      } else {
        if (count >= 4) {
          patterns.repeated.push({ byte: currentByte, count, pos: i - count });
        }
        currentByte = data[i];
        count = 1;
      }
    }

    return patterns;
  };

  const parseAsInt16 = (data) => {
    const result = [];
    for (let i = 0; i < Math.min(data.length, 128); i += 2) {
      if (i + 1 < data.length) {
        const value = (data[i + 1] << 8) | data[i];
        const signed = value > 32767 ? value - 65536 : value;
        result.push(signed);
      }
    }
    return result.slice(0, 10);
  };

  const parseAsInt32 = (data) => {
    const result = [];
    for (let i = 0; i < Math.min(data.length, 128); i += 4) {
      if (i + 3 < data.length) {
        const value = (data[i+3] << 24) | (data[i+2] << 16) | (data[i+1] << 8) | data[i];
        result.push(value >>> 0);
      }
    }
    return result.slice(0, 10);
  };

  const parseAsInt64 = (data) => {
    const result = [];
    for (let i = 0; i < Math.min(data.length, 128); i += 8) {
      if (i + 7 < data.length) {
        const low = (data[i+3] << 24) | (data[i+2] << 16) | (data[i+1] << 8) | data[i];
        const high = (data[i+7] << 24) | (data[i+6] << 16) | (data[i+5] << 8) | data[i+4];
        const value = (BigInt(high >>> 0) << 32n) | BigInt(low >>> 0);
        result.push(value.toString());
      }
    }
    return result.slice(0, 5);
  };

  const compareBuffers = (a, b) => {
    const minLen = Math.min(a.length, b.length);
    let differences = 0;
    const diffPositions = [];

    for (let i = 0; i < minLen; i++) {
      if (a[i] !== b[i]) {
        differences++;
        if (diffPositions.length < 20) {
          diffPositions.push({ pos: i, a: a[i], b: b[i] });
        }
      }
    }

    return {
      sizeDiff: a.length - b.length,
      differences,
      similarity: ((minLen - differences) / minLen * 100).toFixed(2),
      diffPositions
    };
  };

  const suggestAttacks = (a, b) => {
    return [
      {
        name: 'Malleability Attack',
        description: 'LPN-based encryption may be malleable. Try XORing ciphertexts or adding noise patterns.',
        relevant: true
      },
      {
        name: 'Structure Leak',
        description: 'The hint mentions "they parse bytes as int16/int32/int64" - the plaintext encoding may leak information.',
        relevant: true
      },
      {
        name: 'Low Noise Entropy',
        description: 'If noise_entropy_bits=120 is too low, the noise distribution might be exploitable.',
        relevant: true
      },
      {
        name: 'Verification Bypass',
        description: 'Similar to recent VHE attacks (2025), embedded verification values might be extractable.',
        relevant: true
      },
      {
        name: 'Format Oracle',
        description: 'The way plaintexts are encoded (int64 for 64-bit numbers) might provide an oracle.',
        relevant: true
      }
    ];
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 p-8">
      <div className="max-w-6xl mx-auto">
        <div className="bg-gray-800 rounded-lg shadow-2xl p-6 mb-6 border border-blue-500">
          <h1 className="text-3xl font-bold text-blue-400 mb-2 flex items-center gap-3">
            <FileText size={32} />
            PVAC-HFHE Bounty Analyzer
          </h1>
          <p className="text-gray-300 text-sm">
            Analyzing LPN-based homomorphic encryption for the $3,333 bounty challenge
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <label className="block text-blue-400 mb-2 font-semibold">a.ct</label>
            <input
              type="file"
              onChange={(e) => setACt(e.target.files[0])}
              className="w-full text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-blue-600 file:text-white hover:file:bg-blue-700"
            />
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <label className="block text-blue-400 mb-2 font-semibold">b.ct</label>
            <input
              type="file"
              onChange={(e) => setBCt(e.target.files[0])}
              className="w-full text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-blue-600 file:text-white hover:file:bg-blue-700"
            />
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <label className="block text-blue-400 mb-2 font-semibold">pk.bin (optional)</label>
            <input
              type="file"
              onChange={(e) => setPkBin(e.target.files[0])}
              className="w-full text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-green-600 file:text-white hover:file:bg-green-700"
            />
          </div>
        </div>

        <button
          onClick={analyzeFiles}
          className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white font-bold py-3 px-6 rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all shadow-lg mb-6"
        >
          Analyze Files
        </button>

        {analysis && (
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-lg p-6 border border-yellow-500">
              <h2 className="text-2xl font-bold text-yellow-400 mb-4 flex items-center gap-2">
                <AlertCircle size={24} />
                Key Insights
              </h2>
              <div className="space-y-2 text-gray-300">
                <p className="flex items-start gap-2">
                  <span className="text-yellow-400 font-bold">•</span>
                  <span>The hint says "answer is a 64-bit int" - look at int64 interpretations</span>
                </p>
                <p className="flex items-start gap-2">
                  <span className="text-yellow-400 font-bold">•</span>
                  <span>README mentions "two points" to uncover the solution</span>
                </p>
                <p className="flex items-start gap-2">
                  <span className="text-yellow-400 font-bold">•</span>
                  <span>Your observation: "they parse bytes as int16/int32/int64 and pass it off as plaintext"</span>
                </p>
              </div>
            </div>

            {['aCt', 'bCt'].map(key => analysis[key] && (
              <div key={key} className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-xl font-bold text-blue-400 mb-4">{analysis[key].name}</h3>
                <div className="grid md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-400">Size: <span className="text-white">{analysis[key].size} bytes</span></p>
                    <p className="text-gray-400">Entropy: <span className="text-white">{analysis[key].entropy} bits</span></p>
                    <p className="text-gray-400">Zeros: <span className="text-white">{analysis[key].patterns.zeros}</span></p>
                  </div>
                  <div>
                    <p className="text-gray-400 mb-2">First bytes (hex):</p>
                    <code className="text-xs text-green-400 block bg-gray-900 p-2 rounded overflow-x-auto">
                      {analysis[key].interpretations.hex}
                    </code>
                  </div>
                </div>
                <div className="mt-4 space-y-2">
                  <details className="bg-gray-900 p-3 rounded">
                    <summary className="text-blue-400 cursor-pointer font-semibold">As int16 array</summary>
                    <code className="text-xs text-gray-300 block mt-2">
                      {JSON.stringify(analysis[key].interpretations.int16)}
                    </code>
                  </details>
                  <details className="bg-gray-900 p-3 rounded">
                    <summary className="text-blue-400 cursor-pointer font-semibold">As int32 array</summary>
                    <code className="text-xs text-gray-300 block mt-2">
                      {JSON.stringify(analysis[key].interpretations.int32)}
                    </code>
                  </details>
                  <details className="bg-gray-900 p-3 rounded">
                    <summary className="text-purple-400 cursor-pointer font-semibold">As int64 array (IMPORTANT)</summary>
                    <code className="text-xs text-purple-300 block mt-2">
                      {JSON.stringify(analysis[key].interpretations.int64)}
                    </code>
                  </details>
                </div>
              </div>
            ))}

            {analysis.comparison && (
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-xl font-bold text-blue-400 mb-4">Ciphertext Comparison</h3>
                <div className="space-y-2 text-sm text-gray-300">
                  <p>Size difference: <span className="text-white">{analysis.comparison.sizeDiff} bytes</span></p>
                  <p>Total differences: <span className="text-white">{analysis.comparison.differences}</span></p>
                  <p>Similarity: <span className="text-white">{analysis.comparison.similarity}%</span></p>
                </div>
              </div>
            )}

            <div className="bg-gray-800 rounded-lg p-6 border border-red-500">
              <h3 className="text-xl font-bold text-red-400 mb-4 flex items-center gap-2">
                <Info size={20} />
                Suggested Attack Vectors
              </h3>
              <div className="space-y-3">
                {analysis.attacks.map((attack, idx) => (
                  <div key={idx} className="bg-gray-900 p-4 rounded border-l-4 border-red-500">
                    <h4 className="text-red-400 font-bold mb-1">{attack.name}</h4>
                    <p className="text-gray-300 text-sm">{attack.description}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-gradient-to-r from-blue-900 to-purple-900 rounded-lg p-6 border border-blue-500">
              <h3 className="text-xl font-bold text-blue-300 mb-3">Next Steps</h3>
              <ol className="list-decimal list-inside space-y-2 text-gray-300 text-sm">
                <li>Download the actual files from the GitHub repo</li>
                <li>Look for encoding artifacts in the int64 interpretation</li>
                <li>The scheme operates over Fp (p = 2^127 - 1) - check if values exceed this</li>
                <li>Try homomorphic operations (XOR, addition) on the ciphertexts</li>
                <li>Check if the "verification" mechanism leaks plaintext structure</li>
                <li>Params show lpn_tau=1/8 (12.5% noise) - relatively low, might be breakable</li>
              </ol>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BountyAnalyzer;
