#!/usr/bin/env python3
import argparse
from pathlib import Path

from src.trainer import train
from src.detector import scan, write_report


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
        help='Directory containing log files for training'
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
        train(args.log_dir)
    elif args.command == 'scan':
        print('=== Scan Mode ===\n')
        results = scan(args.log_dir)
        write_report(results)


if __name__ == '__main__':
    main()
