"""
Pipeline Performance Profiling Script for ETHIO-AI Defender (Module 19, Step 15).
Measures exact execution times across each individual pipeline stage for a safe synthetic PE.
"""

import time
import io
from app.testing.synthetic_pe import SyntheticPEBuilder
from app.analyzers.file_intake import secure_intake_service
from app.analyzers.hash_analyzer import hash_analyzer_service
from app.analyzers.pe_analyzer import pe_static_analyzer_service
from app.analyzers.section_analyzer import pe_section_analyzer_service
from app.analyzers.entropy_analyzer import entropy_analyzer_service
from app.analyzers.string_analyzer import string_analyzer_service
from app.analyzers.import_analyzer import windows_api_import_analyzer_service
from app.analyzers.indicator_engine import suspicious_indicator_engine_service
from app.analyzers.threat_scoring import threat_scoring_engine_service
from app.analyzers.ethiopian_context import ethiopian_context_engine_service
from app.ai.analyst import ai_security_analyst_service
from app.education.learning_mode import learning_mode_service
from app.reports.generator import security_report_generator_service
from app.pipeline.orchestrator import unified_pipeline_service
from app.db.session import init_db


def benchmark():
    init_db()
    content = SyntheticPEBuilder.create_ethiopian_targeted_pe()
    filename = "benchmark_sample.exe"

    print("=" * 70)
    print("  ETHIO-AI DEFENDER - PIPELINE PERFORMANCE BENCHMARK (STEP 15)")
    print("=" * 70)
    print(f"  Target File : {filename} ({len(content)} bytes)")

    # 1. Intake / Upload Stage
    t0 = time.perf_counter()
    intake_res = secure_intake_service.process_bytes(content, raw_filename=filename)
    t_upload = (time.perf_counter() - t0) * 1000

    # 2. Hash Stage
    t0 = time.perf_counter()
    hash_res = hash_analyzer_service.compute_from_bytes(content)
    t_hash = (time.perf_counter() - t0) * 1000

    # 3. PE Analysis Stage
    t0 = time.perf_counter()
    pe_res = pe_static_analyzer_service.analyze_bytes(content)
    t_pe = (time.perf_counter() - t0) * 1000

    # 4. Section Analysis Stage
    t0 = time.perf_counter()
    sec_res = pe_section_analyzer_service.analyze_bytes(content)
    t_sec = (time.perf_counter() - t0) * 1000

    # 5. Entropy Analysis Stage
    t0 = time.perf_counter()
    ent_res = entropy_analyzer_service.analyze_bytes(content)
    t_ent = (time.perf_counter() - t0) * 1000

    # 6. String Analysis Stage
    t0 = time.perf_counter()
    str_res = string_analyzer_service.analyze_bytes(content)
    t_str = (time.perf_counter() - t0) * 1000

    # 7. Import Analysis Stage
    t0 = time.perf_counter()
    imp_res = windows_api_import_analyzer_service.analyze_bytes(content)
    t_imp = (time.perf_counter() - t0) * 1000

    # 8. Indicator Analysis Stage
    t0 = time.perf_counter()
    ind_res = suspicious_indicator_engine_service.evaluate(
        pe=pe_res, sections=sec_res, entropy=ent_res, strings=str_res, imports=imp_res
    )
    t_ind = (time.perf_counter() - t0) * 1000

    # 9. Threat Scoring Stage
    t0 = time.perf_counter()
    score_res = threat_scoring_engine_service.calculate_score(ind_res.indicators)
    t_score = (time.perf_counter() - t0) * 1000

    # 10. Ethiopian Context Stage
    t0 = time.perf_counter()
    ethio_res = ethiopian_context_engine_service.analyze_context(
        indicators=ind_res.indicators, strings=str_res, threat_score=score_res.score, language="en"
    )
    t_ethio = (time.perf_counter() - t0) * 1000

    evidence = {
        "file_metadata": {"filename": filename, "file_size": len(content)},
        "hashes": hash_res.to_dict(),
        "pe_information": pe_res.to_dict(),
        "sections": sec_res.to_dict(),
        "entropy": ent_res.to_dict(),
        "strings": str_res.to_dict(),
        "imports": imp_res.to_dict(),
        "indicators": ind_res.to_dict(),
        "threat_score": score_res.to_dict(),
        "ethiopian_context": ethio_res.to_dict(),
    }

    # 11. AI Security Analyst Stage (Mocked / Deterministic offline provider)
    t0 = time.perf_counter()
    ai_res = ai_security_analyst_service.analyze(evidence, language="en")
    t_ai = (time.perf_counter() - t0) * 1000

    # 12. Report Generation Stage
    t0 = time.perf_counter()
    rep_res = security_report_generator_service.generate_report(
        evidence=evidence, ai_report=ai_res, language="en", report_id="REP-BENCH-001"
    )
    t_rep = (time.perf_counter() - t0) * 1000

    # 13. End-to-End Orchestrated Pipeline (includes DB Persistence + Audit Logging)
    t0 = time.perf_counter()
    full_res = unified_pipeline_service.execute_pipeline(content, filename=filename, language="en")
    t_total = (time.perf_counter() - t0) * 1000

    print("\n  STAGE TIMINGS BREAKDOWN:")
    print(f"    - Upload / Intake Intake Time      : {t_upload:>8.3f} ms")
    print(f"    - Cryptographic Hash Time         : {t_hash:>8.3f} ms")
    print(f"    - PE Structural Analysis Time     : {t_pe:>8.3f} ms")
    print(f"    - PE Section Analysis Time        : {t_sec:>8.3f} ms")
    print(f"    - Shannon Entropy Analysis Time   : {t_ent:>8.3f} ms")
    print(f"    - String Extraction Time          : {t_str:>8.3f} ms")
    print(f"    - Import / IAT Analysis Time      : {t_imp:>8.3f} ms")
    print(f"    - Indicator Engine Time           : {t_ind:>8.3f} ms")
    print(f"    - Threat Scoring Time             : {t_score:>8.3f} ms")
    print(f"    - Ethiopian Context Analysis Time : {t_ethio:>8.3f} ms")
    print(f"    - AI Security Processing Time     : {t_ai:>8.3f} ms")
    print(f"    - Report Generation Time          : {t_rep:>8.3f} ms")
    print("-" * 70)
    print(f"    - Total End-to-End Analysis Time  : {t_total:>8.3f} ms")
    print("=" * 70)


if __name__ == "__main__":
    benchmark()
