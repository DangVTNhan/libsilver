#!/usr/bin/env node

/**
 * Generate a demo performance report with sample data
 */

import { ReportGenerator } from './report-generator.js';
import fs from 'fs/promises';

// Sample benchmark results
const sampleResults = {
  systemInfo: {
    platform: 'darwin',
    architecture: 'arm64',
    nodeVersion: 'v24.1.0',
    v8Version: '13.6.233.10-node.16',
    cpu: 'Apple M4 Pro',
    cpuCores: 14,
    totalMemory: '48GB',
    freeMemory: '6GB'
  },
  performance: {
    symmetric: {
      'aes-256-gcm': {
        '1KB': {
          nodejs: {
            encrypt: { hz: 381573.23, rme: 0.48, samples: 97, mean: 0.0000026, deviation: 0.0000000125 },
            decrypt: { hz: 694693.08, rme: 0.33, samples: 98, mean: 0.0000014, deviation: 0.0000000046 }
          },
          noble: {
            encrypt: { hz: 48376.36, rme: 0.29, samples: 95, mean: 0.0000207, deviation: 0.0000000060 },
            decrypt: { hz: 51491.49, rme: 0.30, samples: 96, mean: 0.0000194, deviation: 0.0000000058 }
          },
          'libsilver-aws': {
            encrypt: { hz: 878711.57, rme: 0.44, samples: 99, mean: 0.0000011, deviation: 0.0000000049 },
            decrypt: { hz: 1221184.34, rme: 0.41, samples: 99, mean: 0.0000008, deviation: 0.0000000033 }
          },
          'libsilver-rust': {
            encrypt: { hz: 146379.65, rme: 0.70, samples: 97, mean: 0.0000068, deviation: 0.0000000476 },
            decrypt: { hz: 170039.64, rme: 0.43, samples: 98, mean: 0.0000059, deviation: 0.0000000254 }
          }
        },
        '16KB': {
          nodejs: {
            encrypt: { hz: 153901.83, rme: 0.63, samples: 96, mean: 0.0000065, deviation: 0.0000000409 },
            decrypt: { hz: 239592.45, rme: 0.35, samples: 97, mean: 0.0000042, deviation: 0.0000000147 }
          },
          noble: {
            encrypt: { hz: 5139.59, rme: 0.24, samples: 94, mean: 0.0001946, deviation: 0.0000004669 },
            decrypt: { hz: 5177.63, rme: 0.23, samples: 95, mean: 0.0001931, deviation: 0.0000004441 }
          },
          'libsilver-aws': {
            encrypt: { hz: 185058.18, rme: 15.59, samples: 85, mean: 0.0000054, deviation: 0.0000008424 },
            decrypt: { hz: 219954.06, rme: 3.49, samples: 96, mean: 0.0000045, deviation: 0.0000001571 }
          },
          'libsilver-rust': {
            encrypt: { hz: 12855.56, rme: 0.47, samples: 95, mean: 0.0000778, deviation: 0.0000003658 },
            decrypt: { hz: 13291.68, rme: 0.28, samples: 96, mean: 0.0000752, deviation: 0.0000002106 }
          }
        }
      },
      'chacha20-poly1305': {
        '1KB': {
          nodejs: {
            encrypt: { hz: 245123.45, rme: 0.52, samples: 97, mean: 0.0000041, deviation: 0.0000000213 },
            decrypt: { hz: 267891.23, rme: 0.38, samples: 98, mean: 0.0000037, deviation: 0.0000000141 }
          },
          noble: {
            encrypt: { hz: 89234.56, rme: 0.41, samples: 96, mean: 0.0000112, deviation: 0.0000000459 },
            decrypt: { hz: 91567.89, rme: 0.35, samples: 97, mean: 0.0000109, deviation: 0.0000000382 }
          },
          libsilver: {
            encrypt: { hz: 198765.43, rme: 0.48, samples: 98, mean: 0.0000050, deviation: 0.0000000240 },
            decrypt: { hz: 212345.67, rme: 0.42, samples: 97, mean: 0.0000047, deviation: 0.0000000197 }
          }
        }
      }
    },
    hash: {
      sha256: {
        '1KB': {
          nodejs: {
            hash: { hz: 1234567.89, rme: 0.25, samples: 99, mean: 0.0000008, deviation: 0.0000000020 }
          },
          libsilver: {
            hash: { hz: 1456789.12, rme: 0.31, samples: 98, mean: 0.0000007, deviation: 0.0000000022 }
          }
        }
      },
      blake3: {
        '1KB': {
          libsilver: {
            hash: { hz: 2345678.90, rme: 0.28, samples: 99, mean: 0.0000004, deviation: 0.0000000011 }
          }
        }
      }
    }
  },
  memory: {
    symmetric: {
      'aes-256-gcm': {
        nodejs: {
          encrypt: { avgMemoryPerOp: 1024, avgTimePerOp: 0.0026 },
          decrypt: { avgMemoryPerOp: 896, avgTimePerOp: 0.0014 }
        },
        'libsilver-aws': {
          encrypt: { avgMemoryPerOp: 512, avgTimePerOp: 0.0011 },
          decrypt: { avgMemoryPerOp: 448, avgTimePerOp: 0.0008 }
        }
      }
    },
    hash: {
      sha256: {
        nodejs: {
          hash: { avgMemoryPerOp: 256, avgTimePerOp: 0.0008 }
        },
        libsilver: {
          hash: { avgMemoryPerOp: 192, avgTimePerOp: 0.0007 }
        }
      }
    }
  },
  timestamp: new Date().toISOString()
};

async function generateDemoReport() {
  console.log('📊 Generating demo performance report...\n');
  
  try {
    const reportGenerator = new ReportGenerator();
    const reportContent = reportGenerator.generateMarkdownReport(sampleResults);
    
    const reportPath = 'performance_report.md';
    await fs.writeFile(reportPath, reportContent, 'utf8');
    
    console.log(`✅ Demo report generated: ${reportPath}`);
    console.log('\n📄 Report preview:');
    console.log('='.repeat(50));
    console.log(reportContent.substring(0, 1000) + '...\n');
    
  } catch (error) {
    console.error('❌ Error generating demo report:', error.message);
  }
}

generateDemoReport();
