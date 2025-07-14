#!/usr/bin/env node

/**
 * LibSilver Comprehensive Benchmark Runner
 * Orchestrates all benchmark categories and generates performance reports
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import os from 'os';
import fs from 'fs/promises';
import { 
  DATA_SIZES, QUICK_DATA_SIZES, MEMORY_CONFIG, PERFORMANCE_CONFIG, 
  ALGORITHM_CATEGORIES, IMPLEMENTATION_NAMES, REPORT_CONFIG 
} from './config.js';
import { SymmetricBenchmark } from './algorithms/symmetric-benchmark.js';
import { HashBenchmark } from './algorithms/hash-benchmark.js';
import { AsymmetricBenchmark } from './algorithms/asymmetric-benchmark.js';
import { ReportGenerator } from './report-generator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class BenchmarkRunner {
  constructor() {
    this.results = {
      systemInfo: this.getSystemInfo(),
      performance: {},
      memory: {},
      timestamp: new Date().toISOString()
    };
    this.reportGenerator = new ReportGenerator();
  }

  getSystemInfo() {
    return {
      platform: process.platform,
      architecture: process.arch,
      nodeVersion: process.version,
      v8Version: process.versions.v8,
      cpu: os.cpus()[0].model,
      cpuCores: os.cpus().length,
      totalMemory: Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB',
      freeMemory: Math.round(os.freemem() / 1024 / 1024 / 1024) + 'GB'
    };
  }

  async runBenchmarks(options = {}) {
    const {
      categories = Object.keys(ALGORITHM_CATEGORIES),
      quick = false,
      reportOnly = false
    } = options;

    console.log('🚀 LibSilver Comprehensive Benchmark Suite');
    console.log('==========================================\n');
    
    this.printSystemInfo();

    if (reportOnly) {
      console.log('📊 Generating report from existing results...\n');
      await this.generateReport();
      return;
    }

    const dataSizes = quick ? QUICK_DATA_SIZES : DATA_SIZES;
    console.log(`📏 Data sizes: ${dataSizes.map(d => d.name).join(', ')}`);
    console.log(`🏃 Mode: ${quick ? 'Quick' : 'Full'} benchmark\n`);

    // Run performance benchmarks
    for (const category of categories) {
      if (!ALGORITHM_CATEGORIES[category]) {
        console.log(`⚠️  Unknown category: ${category}, skipping...`);
        continue;
      }

      console.log(`\n${'='.repeat(60)}`);
      console.log(`🔍 Category: ${ALGORITHM_CATEGORIES[category].name}`);
      console.log(`${'='.repeat(60)}\n`);

      await this.runCategoryBenchmarks(category, dataSizes);
    }

    // Run memory benchmarks
    if (!quick) {
      console.log(`\n${'='.repeat(60)}`);
      console.log('🧠 Memory Usage Analysis');
      console.log(`${'='.repeat(60)}\n`);
      
      await this.runMemoryBenchmarks(categories);
    }

    // Generate report
    await this.generateReport();
    
    console.log('\n✅ All benchmarks completed successfully!');
    console.log(`📄 Report generated: ${REPORT_CONFIG.outputFile}`);
  }

  printSystemInfo() {
    console.log('💻 System Information:');
    console.log(`   Platform: ${this.results.systemInfo.platform}`);
    console.log(`   Architecture: ${this.results.systemInfo.architecture}`);
    console.log(`   Node.js: ${this.results.systemInfo.nodeVersion}`);
    console.log(`   V8: ${this.results.systemInfo.v8Version}`);
    console.log(`   CPU: ${this.results.systemInfo.cpu}`);
    console.log(`   CPU Cores: ${this.results.systemInfo.cpuCores}`);
    console.log(`   Memory: ${this.results.systemInfo.totalMemory} (${this.results.systemInfo.freeMemory} free)`);
    console.log();
  }

  async runCategoryBenchmarks(category, dataSizes) {
    const categoryConfig = ALGORITHM_CATEGORIES[category];
    const algorithms = categoryConfig.algorithms;

    let benchmark;
    switch (category) {
      case 'symmetric':
        benchmark = new SymmetricBenchmark(PERFORMANCE_CONFIG);
        break;
      case 'hash':
        benchmark = new HashBenchmark(PERFORMANCE_CONFIG);
        break;
      case 'asymmetric':
        benchmark = new AsymmetricBenchmark(PERFORMANCE_CONFIG);
        break;
      case 'signatures':
      case 'kdf':
      case 'pqc':
        console.log(`⚠️  Category ${category} benchmark not yet implemented, skipping...`);
        return;
      default:
        console.log(`⚠️  Unknown category: ${category}, skipping...`);
        return;
    }

    try {
      const results = await benchmark.runBenchmarks(algorithms, dataSizes);
      this.results.performance[category] = results;
    } catch (error) {
      console.error(`❌ Error running ${category} benchmarks:`, error.message);
      this.results.performance[category] = { error: error.message };
    }
  }

  async runMemoryBenchmarks(categories) {
    for (const category of categories) {
      if (!ALGORITHM_CATEGORIES[category]) continue;

      const categoryConfig = ALGORITHM_CATEGORIES[category];
      const algorithms = categoryConfig.algorithms;

      let benchmark;
      switch (category) {
        case 'symmetric':
          benchmark = new SymmetricBenchmark(PERFORMANCE_CONFIG);
          break;
        case 'hash':
          benchmark = new HashBenchmark(PERFORMANCE_CONFIG);
          break;
        case 'asymmetric':
          benchmark = new AsymmetricBenchmark(PERFORMANCE_CONFIG);
          break;
        default:
          console.log(`⚠️  Memory benchmark for ${category} not yet implemented, skipping...`);
          continue;
      }

      try {
        const memoryResults = await benchmark.measureMemory(
          algorithms, 
          MEMORY_CONFIG.testDataSize, 
          MEMORY_CONFIG.iterations
        );
        this.results.memory[category] = memoryResults;
      } catch (error) {
        console.error(`❌ Error running ${category} memory benchmarks:`, error.message);
        this.results.memory[category] = { error: error.message };
      }
    }
  }

  async generateReport() {
    try {
      const reportPath = join(__dirname, REPORT_CONFIG.outputFile);
      const reportContent = this.reportGenerator.generateMarkdownReport(this.results);
      
      await fs.writeFile(reportPath, reportContent, 'utf8');
      console.log(`📄 Performance report saved to: ${reportPath}`);
    } catch (error) {
      console.error('❌ Error generating report:', error.message);
    }
  }
}

// CLI argument parsing
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    categories: Object.keys(ALGORITHM_CATEGORIES),
    quick: false,
    reportOnly: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--quick':
        options.quick = true;
        break;
      case '--report-only':
        options.reportOnly = true;
        break;
      case '--category':
        if (i + 1 < args.length) {
          options.categories = [args[++i]];
        }
        break;
      case '--help':
        console.log(`
LibSilver Benchmark Runner

Usage: node benchmark-runner.js [options]

Options:
  --quick              Run quick benchmark with fewer data sizes
  --report-only        Generate report from existing results only
  --category <name>    Run benchmarks for specific category only
                       Categories: ${Object.keys(ALGORITHM_CATEGORIES).join(', ')}
  --help              Show this help message

Examples:
  node benchmark-runner.js                    # Run all benchmarks
  node benchmark-runner.js --quick            # Quick benchmark
  node benchmark-runner.js --category symmetric  # Only symmetric encryption
  node benchmark-runner.js --report-only      # Generate report only
        `);
        process.exit(0);
        break;
    }
  }

  return options;
}

// Main execution
async function main() {
  try {
    const options = parseArgs();
    const runner = new BenchmarkRunner();
    await runner.runBenchmarks(options);
  } catch (error) {
    console.error('💥 Benchmark failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { BenchmarkRunner };
