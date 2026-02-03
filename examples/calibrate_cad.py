#!/usr/bin/env python3
"""
CAD Calibration Tool - Improved staged calibration workflow
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from common import create_radio

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def get_test_ranges(spreading_factor: int) -> Tuple[range, range]:
    """Get CAD test ranges based on spreading factor"""
    sf_ranges = {
        7: (range(16, 29, 1), range(6, 15, 1)),
        8: (range(16, 29, 1), range(6, 15, 1)),
        9: (range(18, 31, 1), range(7, 16, 1)),
        10: (range(20, 33, 1), range(8, 16, 1)),
        11: (range(22, 35, 1), range(9, 17, 1)),
        12: (range(24, 37, 1), range(10, 18, 1)),
    }
    return sf_ranges.get(spreading_factor, sf_ranges[8])


def get_status_text(detection_rate: float) -> str:
    """Get status text based on detection rate"""
    if detection_rate == 0:
        return "QUIET"
    elif detection_rate < 10:
        return "LOW"
    elif detection_rate < 30:
        return "MED"
    else:
        return "HIGH"


async def test_cad_config(radio, det_peak: int, det_min: int, samples: int = 8) -> Dict[str, Any]:
    """Test a single CAD configuration with multiple samples"""
    detections = 0
    for _ in range(samples):
        try:
            result = await radio.perform_cad(det_peak=det_peak, det_min=det_min, timeout=0.6)
            if result:
                detections += 1
        except Exception:
            pass
        await asyncio.sleep(0.03)

    return {
        "det_peak": det_peak,
        "det_min": det_min,
        "samples": samples,
        "detections": detections,
        "detection_rate": (detections / samples) * 100,
    }


async def stage1_broad_scan(radio, peak_range: range, min_range: range) -> List[Dict[str, Any]]:
    """Stage 1: Broad scan - 8 samples, stop after 10 consecutive quiet configs"""
    logger.info("Stage 1: Broad scan (8 samples each)")
    results = []
    consecutive_quiet = 0
    total = len(peak_range) * len(min_range)
    current = 0

    for det_peak in peak_range:
        for det_min in min_range:
            current += 1
            result = await test_cad_config(radio, det_peak, det_min, 8)
            results.append(result)

            rate = result["detection_rate"]
            status = get_status_text(rate)
            logger.info(
                f"[{current:3d}/{total}] peak={det_peak:2d} min={det_min:2d} -> {result['detections']:2d}/8 ({rate:5.1f}%) {status}"
            )

            # Track consecutive quiet configs
            if rate == 0:
                consecutive_quiet += 1
                if consecutive_quiet >= 10:
                    logger.info(f"Found 10 consecutive quiet configs, stopping broad scan early")
                    break
            else:
                consecutive_quiet = 0

        if consecutive_quiet >= 10:
            break

    return results


async def stage2_focused_scan(radio, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stage 2: Focused scan - 16 samples on configs with 0-20% detection"""
    good_candidates = [c for c in candidates if c["detection_rate"] <= 20]
    if len(good_candidates) > 20:
        good_candidates = sorted(
            good_candidates, key=lambda x: (x["detection_rate"], x["det_peak"])
        )[:20]

    logger.info(f"Stage 2: Focused scan on {len(good_candidates)} candidates (16 samples each)")
    results = []

    for i, candidate in enumerate(good_candidates, 1):
        result = await test_cad_config(radio, candidate["det_peak"], candidate["det_min"], 16)
        results.append(result)

        rate = result["detection_rate"]
        status = get_status_text(rate)
        logger.info(
            f"[{i:2d}/{len(good_candidates)}] peak={result['det_peak']:2d} min={result['det_min']:2d} -> {result['detections']:2d}/16 ({rate:5.1f}%) {status}"
        )

        # Stop if we have 5 excellent configs
        excellent = [r for r in results if r["detection_rate"] <= 5]
        if len(excellent) >= 5:
            logger.info(f"Found 5 excellent configs (<=5% detection), moving to next stage")
            break

    return results


async def stage3_fine_tuning(radio, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stage 3: Fine tuning - 32 samples on top 5 quietest configs"""
    top5 = sorted(candidates, key=lambda x: (x["detection_rate"], x["det_peak"]))[:5]

    logger.info(f"Stage 3: Fine tuning on top {len(top5)} configs (32 samples each)")
    results = []

    for i, candidate in enumerate(top5, 1):
        result = await test_cad_config(radio, candidate["det_peak"], candidate["det_min"], 32)
        results.append(result)

        rate = result["detection_rate"]
        status = get_status_text(rate)
        logger.info(
            f"[{i}/{len(top5)}] peak={result['det_peak']:2d} min={result['det_min']:2d} -> {result['detections']:2d}/32 ({rate:5.1f}%) {status}"
        )

    return results


async def stage4_validation(radio, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stage 4: Validation - 64 samples on best 1-2 configs, 3 consecutive runs"""
    best_configs = sorted(candidates, key=lambda x: (x["detection_rate"], x["det_peak"]))[:2]

    logger.info(f"Stage 4: Validation on best {len(best_configs)} config(s) (64 samples x 3 runs)")
    final_results = []

    for i, candidate in enumerate(best_configs, 1):
        logger.info(
            f"Validating config {i}: peak={candidate['det_peak']}, min={candidate['det_min']}"
        )

        runs = []
        stable = True

        for run in range(3):
            result = await test_cad_config(radio, candidate["det_peak"], candidate["det_min"], 64)
            runs.append(result)

            rate = result["detection_rate"]
            logger.info(f"  Run {run+1}/3: {result['detections']:2d}/64 ({rate:4.1f}%)")

            # Check stability (within ±5% of first run)
            if run > 0:
                diff = abs(result["detection_rate"] - runs[0]["detection_rate"])
                if diff > 5.0:
                    stable = False

        # Average the runs
        avg_detections = sum(r["detections"] for r in runs) / len(runs)
        avg_rate = (avg_detections / 64) * 100

        final_result = {
            "det_peak": candidate["det_peak"],
            "det_min": candidate["det_min"],
            "samples": 64 * 3,
            "detections": int(avg_detections * 3),
            "detection_rate": avg_rate,
            "stable": stable,
            "runs": runs,
        }

        status = "STABLE" if stable else "UNSTABLE"
        logger.info(f"  Average: {final_result['detections']:3d}/192 ({avg_rate:4.1f}%) {status}")

        final_results.append(final_result)

    return final_results


async def perform_staged_calibration(
    radio, peak_range: range, min_range: range
) -> List[Dict[str, Any]]:
    """Perform the complete 4-stage calibration process"""
    # Stage 1: Broad scan
    stage1_results = await stage1_broad_scan(radio, peak_range, min_range)

    # Stage 2: Focused scan
    stage2_results = await stage2_focused_scan(radio, stage1_results)

    # Stage 3: Fine tuning
    stage3_results = await stage3_fine_tuning(radio, stage2_results)

    # Stage 4: Validation
    stage4_results = await stage4_validation(radio, stage3_results)

    return stage4_results


async def calibrate_cad(radio_type: str = "waveshare", staged: bool = True):
    """Main CAD calibration function with staged workflow"""
    if radio_type == "kiss-tnc":
        logger.error("CAD not supported on KISS-TNC. Use SX1262 radios only.")
        return None

    logger.info(f"CAD Calibration: {radio_type} radio")
    if staged:
        logger.info("Using 4-stage calibration workflow")

    radio = None
    try:
        # Create and verify radio
        radio = create_radio(radio_type)
        from pymc_core.hardware.sx1262_wrapper import SX1262Radio

        if not isinstance(radio, SX1262Radio):
            logger.error(f"Need SX1262Radio, got {type(radio).__name__}")
            return None

        # Initialize
        radio.begin()
        config = radio.get_status()
        sf = config.get("spreading_factor", 8)
        logger.info(
            f"Radio: {config['frequency']/1e6:.1f}MHz, SF{sf}, {config['bandwidth']/1000:.1f}kHz"
        )

        await asyncio.sleep(1.0)  # Radio settle time

        # Get test ranges
        peak_range, min_range = get_test_ranges(sf)
        logger.info(
            f"Testing peak {peak_range.start}-{peak_range.stop-1}, min {min_range.start}-{min_range.stop-1}"
        )

        # Perform calibration
        if staged:
            results = await perform_staged_calibration(radio, peak_range, min_range)

            logger.info("=" * 60)
            logger.info("FINAL CALIBRATION RESULTS")
            logger.info("=" * 60)

            for i, result in enumerate(results, 1):
                stable_text = "STABLE" if result.get("stable", False) else "UNSTABLE"
                logger.info(
                    f"Config {i}: peak={result['det_peak']:2d}, min={result['det_min']:2d} -> "
                    f"{result['detections']:3d}/192 ({result['detection_rate']:4.1f}%) {stable_text}"
                )

            if results:
                best = min(results, key=lambda x: (x["detection_rate"], x["det_peak"]))
                logger.info(
                    f"\nRECOMMENDED: peak={best['det_peak']}, min={best['det_min']} "
                    f"({best['detection_rate']:.1f}% detection)"
                )
        else:
            # Simple sweep fallback
            results = []
            total = len(peak_range) * len(min_range)
            current = 0
            for det_peak in peak_range:
                for det_min in min_range:
                    current += 1
                    result = await test_cad_config(radio, det_peak, det_min, 8)
                    results.append(result)

                    rate = result["detection_rate"]
                    status = get_status_text(rate)
                    logger.info(
                        f"[{current:3d}/{total}] peak={det_peak:2d} min={det_min:2d} -> {result['detections']:2d}/8 ({rate:5.1f}%) {status}"
                    )

        return results

    except Exception as e:
        logger.error(f"Calibration failed: {e}")
        return None
    finally:
        if radio:
            radio.cleanup()
            logger.info("Cleanup complete")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CAD Calibration Tool with Staged Workflow")
    parser.add_argument(
        "--radio",
        choices=["waveshare", "uconsole", "meshadv-mini", "kiss-tnc", "kiss-modem"],
        default="waveshare",
        help="Radio type",
    )
    parser.add_argument(
        "--simple", action="store_true", help="Use simple sweep instead of staged workflow"
    )
    args = parser.parse_args()

    logger.info("CAD Calibration Tool")
    if not args.simple:
        logger.info("4-Stage Workflow: Broad->Focused->Fine->Validation")
    logger.info("Lower detection % = better for mesh networking")

    try:
        result = asyncio.run(calibrate_cad(args.radio, staged=not args.simple))
        if result:
            logger.info("Calibration complete!")
        else:
            exit(1)
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        exit(1)


if __name__ == "__main__":
    main()
