#!/usr/bin/env python3
import argparse
from pathlib import Path

from src.trainer import train
from src.detector import scan, write_report, write_excerpts
from src.llm_reporter import write_llm_report


def main():
    parser = argparse.ArgumentParser(
        description='Wi-Fi Log Anomaly Detection Pipeline'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Train command
    train_parser = subparsers.add_parser('train', help='Train models on labeled log files')
    train_parser.add_argument(
        'log_dir',
        type=Path,
        help='Directory containing normal log files for training'
    )
    train_parser.add_argument(
        '--anomaly-dir',
        type=Path,
        default=None,
        dest='anomaly_dir',
        help='Directory of known anomalous logs for supervised classifier training'
    )

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan log files for anomalies')
    scan_parser.add_argument(
        'log_dir',
        type=Path,
        help='Directory containing log files to scan'
    )

    args = parser.parse_args()

    if args.command == 'train':
        print('=== Training Mode ===\n')
        train(args.log_dir, anomaly_dir=args.anomaly_dir)
    elif args.command == 'scan':
        print('=== Scan Mode ===\n')
        results, file_data = scan(args.log_dir)
        write_report(results)
        print('\nGenerating detailed outputs...')
        write_excerpts(file_data)
        write_llm_report(file_data)


if __name__ == '__main__':
    main()
