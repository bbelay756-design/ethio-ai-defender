"""
Module 12 & 16: Educational Learning Lab API Router.

Provides dedicated endpoints for:
1. Concept Breakdowns & Theory across 14 Reverse-Engineering Topics.
2. Curated Safe Practice Lab Binaries (Synthetic In-Memory PEs).
3. Real Static Analysis Pipeline Execution on Safe Practice Samples.
4. Interactive Reverse-Engineering Knowledge Quizzes with Detailed Rationales.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth.dependencies import get_current_user
from app.db.models import UserModel
from app.education.topics import EDUCATIONAL_TOPICS_DATABASE
from app.education.learning_mode import learning_mode_service
from app.testing.synthetic_pe import SyntheticPEBuilder
from app.pipeline.orchestrator import unified_pipeline_service
from app.core.logger import logger

router = APIRouter(prefix="/api/learning", tags=["Educational Learning Lab"])


# ============================================================================
# SCHEMAS
# ============================================================================

class TopicSummary(BaseModel):
    id: str
    title: str
    category: str
    what_is_it_summary: str


class VisualAnatomyField(BaseModel):
    offset: str
    size: str
    field_name: str
    description: str
    sample_value: str


class VisualAnatomy(BaseModel):
    structure_name: str
    summary: str
    fields: List[VisualAnatomyField]


class TopicDetail(BaseModel):
    id: str
    title: str
    category: str
    difficulty_level: str
    language: str
    what_is_it: str
    why_it_matters: str
    explanation: str
    proves_malicious: str
    what_to_learn_next: List[str]
    visual_anatomy: Optional[VisualAnatomy] = None
    related_topics: List[str]


class PracticeSample(BaseModel):
    id: str
    filename: str
    title: str
    difficulty: str
    description: str
    category: str
    key_learning_points: List[str]
    expected_findings: List[str]
    file_type: str
    approx_size_bytes: int


class QuizOption(BaseModel):
    id: str
    text: str


class QuizQuestion(BaseModel):
    id: str
    topic: str
    difficulty: str
    question: str
    options: List[QuizOption]
    hint: str


class QuizAnswerSubmission(BaseModel):
    question_id: str
    selected_option_id: str


class QuizEvaluationRequest(BaseModel):
    answers: List[QuizAnswerSubmission]


class QuestionResult(BaseModel):
    question_id: str
    is_correct: bool
    selected_option_id: str
    correct_option_id: str
    explanation: str


class QuizEvaluationResponse(BaseModel):
    total_questions: int
    correct_count: int
    score_percentage: float
    passed: bool
    results: List[QuestionResult]


# ============================================================================
# KNOWLEDGE BASE & VISUAL ANATOMY DATA
# ============================================================================

VISUAL_ANATOMIES: Dict[str, VisualAnatomy] = {
    "DOS_HEADER": VisualAnatomy(
        structure_name="IMAGE_DOS_HEADER (64 Bytes)",
        summary="Legacy MS-DOS header present at offset 0x00000000 of every PE binary.",
        fields=[
            VisualAnatomyField(offset="0x00", size="2 Bytes (WORD)", field_name="e_magic", description="DOS Magic Bytes ('MZ' or 0x5A4D)", sample_value="0x5A4D ('MZ')"),
            VisualAnatomyField(offset="0x02", size="2 Bytes (WORD)", field_name="e_cblp", description="Bytes on last page of file", sample_value="0x0090"),
            VisualAnatomyField(offset="0x04", size="2 Bytes (WORD)", field_name="e_cp", description="Pages in file", sample_value="0x0003"),
            VisualAnatomyField(offset="0x3C", size="4 Bytes (DWORD)", field_name="e_lfanew", description="File offset pointing to the PE NT Header", sample_value="0x00000080 (128d)"),
        ]
    ),
    "PE_HEADER": VisualAnatomy(
        structure_name="IMAGE_NT_HEADERS (Signature + COFF + Optional Header)",
        summary="Main control structures dictating CPU architecture, subsystem, and execution entry.",
        fields=[
            VisualAnatomyField(offset="0x00", size="4 Bytes (DWORD)", field_name="Signature", description="PE Signature 'PE\\0\\0'", sample_value="0x00004550 ('PE\\0\\0')"),
            VisualAnatomyField(offset="0x04", size="2 Bytes (WORD)", field_name="Machine", description="Target CPU architecture (x86, x64, ARM)", sample_value="0x014C (x86) / 0x8664 (x64)"),
            VisualAnatomyField(offset="0x06", size="2 Bytes (WORD)", field_name="NumberOfSections", description="Total section headers in section table", sample_value="0x0004 (4 sections)"),
            VisualAnatomyField(offset="0x08", size="4 Bytes (DWORD)", field_name="TimeDateStamp", description="Compile timestamp in Unix Epoch seconds", sample_value="0x65A00000"),
            VisualAnatomyField(offset="0x28", size="4 Bytes (DWORD)", field_name="AddressOfEntryPoint", description="RVA where execution begins", sample_value="0x00001000"),
            VisualAnatomyField(offset="0x34", size="4/8 Bytes", field_name="ImageBase", description="Preferred virtual memory load address", sample_value="0x00400000 / 0x140000000"),
            VisualAnatomyField(offset="0x5C", size="2 Bytes (WORD)", field_name="Subsystem", description="GUI (2) vs Console CLI (3)", sample_value="0x0003 (IMAGE_SUBSYSTEM_WINDOWS_CUI)"),
            VisualAnatomyField(offset="0x5E", size="2 Bytes (WORD)", field_name="DllCharacteristics", description="Security mitigations (ASLR, DEP, CFG)", sample_value="0x8140 (DYNAMIC_BASE | NX_COMPAT)"),
        ]
    ),
    "SECTIONS": VisualAnatomy(
        structure_name="IMAGE_SECTION_HEADER (40 Bytes per Section)",
        summary="Defines mapped memory permissions and disk-to-RAM mapping bounds.",
        fields=[
            VisualAnatomyField(offset="0x00", size="8 Bytes (BYTE[8])", field_name="Name", description="Null-padded section name string", sample_value="'.text\\0\\0\\0'"),
            VisualAnatomyField(offset="0x08", size="4 Bytes (DWORD)", field_name="VirtualSize", description="Total size in bytes when loaded in RAM", sample_value="0x00002400"),
            VisualAnatomyField(offset="0x0C", size="4 Bytes (DWORD)", field_name="VirtualAddress", description="Relative Virtual Address (RVA) in RAM", sample_value="0x00001000"),
            VisualAnatomyField(offset="0x10", size="4 Bytes (DWORD)", field_name="SizeOfRawData", description="Size of initialized data on disk", sample_value="0x00002600"),
            VisualAnatomyField(offset="0x14", size="4 Bytes (DWORD)", field_name="PointerToRawData", description="File offset to section bytes on disk", sample_value="0x00000400"),
            VisualAnatomyField(offset="0x24", size="4 Bytes (DWORD)", field_name="Characteristics", description="Memory permissions (Read, Write, Execute)", sample_value="0x60000020 (MEM_EXECUTE | MEM_READ | CODE)"),
        ]
    ),
    "IMPORTS": VisualAnatomy(
        structure_name="IMAGE_IMPORT_DESCRIPTOR (20 Bytes per DLL)",
        summary="Directs the Windows loader which dynamic libraries and API exports to resolve.",
        fields=[
            VisualAnatomyField(offset="0x00", size="4 Bytes (DWORD)", field_name="OriginalFirstThunk", description="RVA to Import Lookup Table (ILT/INT)", sample_value="0x00003000"),
            VisualAnatomyField(offset="0x04", size="4 Bytes (DWORD)", field_name="TimeDateStamp", description="0 or bound timestamp", sample_value="0x00000000"),
            VisualAnatomyField(offset="0x0C", size="4 Bytes (DWORD)", field_name="Name", description="RVA to ASCII DLL name string", sample_value="0x00003080 ('KERNEL32.dll')"),
            VisualAnatomyField(offset="0x10", size="4 Bytes (DWORD)", field_name="FirstThunk", description="RVA to Import Address Table (IAT) rewritten by loader", sample_value="0x00003040"),
        ]
    ),
}

PRACTICE_SAMPLES_CATALOG: List[PracticeSample] = [
    PracticeSample(
        id="lab-01-benign-cli",
        filename="safe_cli_utility.exe",
        title="1. Standard Benign CLI Utility",
        difficulty="BEGINNER",
        category="Baseline PE Analysis",
        description="A clean, standard Windows command-line utility with ordinary section layout, low Shannon entropy, and typical KERNEL32 imports.",
        key_learning_points=[
            "Standard DOS & PE headers with typical ASLR/DEP flags",
            "Shannon entropy below 5.0 indicating uncompressed plaintext code",
            "Clear, non-obfuscated ASCII string table",
            "Standard .text (Execute+Read) and .data (Read+Write) section permissions conforming to W^X"
        ],
        expected_findings=[
            "Subsystem: Console (IMAGE_SUBSYSTEM_WINDOWS_CUI)",
            "Entropy: ~4.15 (Low / Unpacked)",
            "Risk Score: 0 (BENIGN)"
        ],
        file_type="PE32 Executable (.exe)",
        approx_size_bytes=1536
    ),
    PracticeSample(
        id="lab-02-packed-upx",
        filename="upx_packed_demo.exe",
        title="2. Packed Binary Simulator (UPX)",
        difficulty="INTERMEDIATE",
        category="Packing & Entropy",
        description="Simulates a binary compressed with the UPX packer. Demonstrates high entropy, non-standard section headers (UPX0, UPX1), and compressed payload stubs.",
        key_learning_points=[
            "High Shannon entropy (> 7.5) in payload section UPX1",
            "Section characteristics violating W^X (Write + Execute enabled simultaneously)",
            "RawSize vs VirtualSize disparity (UPX0 has 0 raw size but large virtual allocation)",
            "Minimal import table relying on LoadLibraryA and GetProcAddress for dynamic unpacking"
        ],
        expected_findings=[
            "High Entropy Alert (> 7.50)",
            "Unusual Section Names: UPX0, UPX1",
            "Suspicious Capability: Dynamic Code Unpacking"
        ],
        file_type="PE32 Executable (.exe)",
        approx_size_bytes=2560
    ),
    PracticeSample(
        id="lab-03-crypto-dll",
        filename="crypto_defense_helper.dll",
        title="3. Security DLL & Cryptographic Module",
        difficulty="INTERMEDIATE",
        category="Libraries & Cryptography",
        description="A Windows Dynamic Link Library (.dll) exhibiting cryptographic API imports and standard export table structures.",
        key_learning_points=[
            "IMAGE_FILE_DLL characteristic bit set in COFF Header",
            "Cryptographic API imports: BCryptGenRandom, CryptAcquireContextA, CryptEncrypt",
            "DLL entry point (DllMain) handling DLL_PROCESS_ATTACH notifications",
            "Export table directory pointers"
        ],
        expected_findings=[
            "File Type: Dynamic Link Library (.dll)",
            "Import Categories: CRYPTO, MEMORY",
            "Risk Score: Low/Moderate"
        ],
        file_type="PE32 Dynamic Link Library (.dll)",
        approx_size_bytes=2048
    ),
    PracticeSample(
        id="lab-04-suspicious-stager",
        filename="suspicious_stager_demo.exe",
        title="4. In-Memory Stager & Process Injection Simulator",
        difficulty="ADVANCED",
        category="API Correlation & TTPs",
        description="Contains static references to process injection APIs, persistence registry keys, and network communication indicators.",
        key_learning_points=[
            "Correlated process injection primitives: VirtualAlloc, WriteProcessMemory, CreateRemoteThread",
            "Persistence registry paths: Run key persistence in HKCU",
            "Network C2 indicators: Embedded IP addresses and URL paths",
            "Critical reminder: Static presence of APIs indicates capability, not necessarily live execution"
        ],
        expected_findings=[
            "Correlated Indicators: Process Injection & Network Communication",
            "Sensitive Registry Paths Detected",
            "Risk Score: Suspicious / High"
        ],
        file_type="PE32 Executable (.exe)",
        approx_size_bytes=2560
    ),
    PracticeSample(
        id="lab-05-ethio-cyber",
        filename="ethio_critical_infra_mock.exe",
        title="5. Ethiopian Cyber Threat Triage Sample",
        difficulty="ADVANCED",
        category="National Infrastructure Triage",
        description="Synthetic binary incorporating Ethiopian financial/telecom endpoints, Amharic strings, and government domain references.",
        key_learning_points=[
            "Targeted context extraction: Ethiopian banking URLs (CBE), Ethio Telecom telebirr APIs, and INSA domains",
            "UTF-8 / Unicode Amharic string extraction (የይለፍ ቃል, ቴሌብር)",
            "Threat indicator correlation for national SOC triage",
            "Bilingual reporting in English and Amharic"
        ],
        expected_findings=[
            "Targeted Ethiopian Context: Banking & Telecom Indicators",
            "Unicode Strings: Amharic script detected",
            "SOC Alert: High-Priority National Infrastructure Triage"
        ],
        file_type="PE32 Executable (.exe)",
        approx_size_bytes=2560
    ),
]

QUIZ_QUESTION_BANK = [
    {
        "id": "q1",
        "topic": "PE_FORMAT",
        "difficulty": "BEGINNER",
        "question": "What is the primary purpose of the 'e_lfanew' field located at offset 0x3C in the DOS Header?",
        "options": [
            {"id": "a", "text": "It specifies the file encryption key."},
            {"id": "b", "text": "It is a 4-byte offset pointer that tells the OS loader where the PE NT Header begins."},
            {"id": "c", "text": "It stores the size of the text strings in the executable."},
            {"id": "d", "text": "It terminates the program if running in DOS mode."}
        ],
        "correct_id": "b",
        "hint": "Think about how Windows skips past the legacy 16-bit DOS stub to find the 32/64-bit headers.",
        "explanation": "Offset 0x3C (IMAGE_DOS_HEADER.e_lfanew) stores a 32-bit integer that gives the exact file offset of the real IMAGE_NT_HEADERS ('PE\\0\\0')."
    },
    {
        "id": "q2",
        "topic": "ENTROPY",
        "difficulty": "BEGINNER",
        "question": "If an executable section displays a Shannon Entropy score of 7.85 out of 8.0, what does this mathematically indicate?",
        "options": [
            {"id": "a", "text": "The section is definitely malicious and contains ransomware."},
            {"id": "b", "text": "The section contains high randomness, characteristic of compressed data, encrypted payloads, or software packing."},
            {"id": "c", "text": "The section has corrupted bytes and cannot be loaded by Windows."},
            {"id": "d", "text": "The section contains only ASCII printable text."}
        ],
        "correct_id": "b",
        "hint": "Shannon entropy measures information density and randomness on a 0.0 to 8.0 scale.",
        "explanation": "Entropy > 7.2 indicates high byte unpredictability. While common in packed or encrypted malware, legitimate installers and compressed media also have high entropy. It does NOT alone prove malicious intent."
    },
    {
        "id": "q3",
        "topic": "WINDOWS_APIS",
        "difficulty": "INTERMEDIATE",
        "question": "An analyst discovers 'VirtualProtect' in the import table. Does this single finding prove that the binary is malicious?",
        "options": [
            {"id": "a", "text": "Yes, VirtualProtect is only used by kernel rootkits."},
            {"id": "b", "text": "No, legitimate compilers, JIT runtimes, and software protectors legitimately use VirtualProtect to manage page memory permissions."},
            {"id": "c", "text": "Yes, modifying memory protection is prohibited by Windows."},
            {"id": "d", "text": "Only if the file extension is .dll."}
        ],
        "correct_id": "b",
        "hint": "Remember the core defensive principle: static API capability alone does not prove malicious intent.",
        "explanation": "VirtualProtect changes memory page permissions (such as making a page executable). Legitimate Just-In-Time (JIT) engines, DRM wrappers, and debugging tools use it legitimately."
    },
    {
        "id": "q4",
        "topic": "SECTIONS",
        "difficulty": "INTERMEDIATE",
        "question": "Why does a section marked with both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE (W+X) trigger a defensive security warning?",
        "options": [
            {"id": "a", "text": "It violates the Write XOR Execute (W^X / DEP) security principle, allowing self-modifying or dynamically unpacked code to execute in writable memory."},
            {"id": "b", "text": "Windows 10/11 will refuse to load any executable with write permissions."},
            {"id": "c", "text": "It increases the file size by 50%."},
            {"id": "d", "text": "It causes the compiler to crash."}
        ],
        "correct_id": "a",
        "hint": "Think about Data Execution Prevention (DEP) and preventing arbitrary code execution in buffer memory.",
        "explanation": "Defensive architectures enforce W^X: memory should either be writable or executable, but not both. Violations often indicate packed code, shellcode buffers, or JIT engines."
    },
    {
        "id": "q5",
        "topic": "THREAT_INDICATORS",
        "difficulty": "ADVANCED",
        "question": "Which combination of Windows API imports statically indicates potential remote process injection capability?",
        "options": [
            {"id": "a", "text": "GetStdHandle + WriteFile + ExitProcess"},
            {"id": "b", "text": "OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"},
            {"id": "c", "text": "MessageBoxA + SetWindowTextA + ShowWindow"},
            {"id": "d", "text": "FindFirstFileA + FindNextFileA + CopyFileA"}
        ],
        "correct_id": "b",
        "hint": "Look for APIs that open a target process, allocate memory in its address space, write bytes, and spawn an execution thread.",
        "explanation": "The classic process injection pattern opens a target process, allocates memory in the remote address space, copies shellcode with WriteProcessMemory, and creates a thread in the foreign process."
    }
]


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.get("/topics", response_model=List[TopicSummary], summary="List all 14 reverse-engineering educational topics")
def list_learning_topics(
    lang: str = Query("en", description="Language code: 'en' (English) or 'am' (Amharic)"),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Returns high-level catalog of all 14 structured reverse-engineering concepts.
    """
    results: List[TopicSummary] = []
    for topic_id, topic_data in EDUCATIONAL_TOPICS_DATABASE.items():
        lang_data = topic_data.get(lang, topic_data.get("en", {}))
        what_is_it = lang_data.get("what_is_it", "")
        summary_text = what_is_it[:140] + "..." if len(what_is_it) > 140 else what_is_it

        results.append(TopicSummary(
            id=topic_id,
            title=topic_data.get("title", topic_id),
            category=topic_data.get("category", "General"),
            what_is_it_summary=summary_text
        ))
    return results


@router.get("/topics/{topic_id}", response_model=TopicDetail, summary="Get full breakdown of an educational concept")
def get_topic_detail(
    topic_id: str,
    lang: str = Query("en", description="Language code: 'en' or 'am'"),
    level: str = Query("BEGINNER", description="Difficulty level: 'BEGINNER' or 'ADVANCED'"),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Returns comprehensive educational breakdown for a specific topic with visual header anatomy,
    beginner/advanced explanations, and related next learning steps.
    """
    topic_key = topic_id.upper().strip()
    if topic_key not in EDUCATIONAL_TOPICS_DATABASE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Educational topic '{topic_id}' not found. Available topics: {list(EDUCATIONAL_TOPICS_DATABASE.keys())}"
        )

    topic_data = EDUCATIONAL_TOPICS_DATABASE[topic_key]
    lang_data = topic_data.get(lang, topic_data.get("en", {}))
    explanation = lang_data.get("beginner_explanation" if level.upper() == "BEGINNER" else "advanced_explanation", "")

    # Related topics
    all_keys = list(EDUCATIONAL_TOPICS_DATABASE.keys())
    cur_idx = all_keys.index(topic_key)
    related = [all_keys[(cur_idx - 1) % len(all_keys)], all_keys[(cur_idx + 1) % len(all_keys)]]

    return TopicDetail(
        id=topic_key,
        title=topic_data.get("title", topic_key),
        category=topic_data.get("category", "General"),
        difficulty_level=level.upper(),
        language=lang,
        what_is_it=lang_data.get("what_is_it", ""),
        why_it_matters=lang_data.get("why_it_matters", ""),
        explanation=explanation,
        proves_malicious=lang_data.get("proves_malicious", "No. This feature alone does not prove malicious behavior."),
        what_to_learn_next=lang_data.get("what_to_learn_next", []),
        visual_anatomy=VISUAL_ANATOMIES.get(topic_key),
        related_topics=related
    )


@router.get("/practice-samples", response_model=List[PracticeSample], summary="List all safe educational practice lab binaries")
def list_practice_samples(
    current_user: UserModel = Depends(get_current_user)
):
    """
    Returns curated safe synthetic educational binaries that students can load and inspect
    safely without any live malware risk.
    """
    return PRACTICE_SAMPLES_CATALOG


@router.post("/practice-samples/{sample_id}/load", summary="Load and analyze a safe educational practice binary in the lab")
def load_and_analyze_practice_sample(
    sample_id: str,
    lang: str = Query("en", description="Language code: 'en' or 'am'"),
    current_user: UserModel = Depends(get_current_user)
):
    """
    Constructs the selected safe educational binary in-memory, runs the real 15-stage deterministic
    static analysis pipeline, and stores the resulting analysis record under the student's profile.
    """
    sample_meta = next((s for s in PRACTICE_SAMPLES_CATALOG if s.id == sample_id), None)
    if not sample_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Practice sample '{sample_id}' not found."
        )

    # Build safe in-memory synthetic PE binary according to sample type
    if sample_id == "lab-01-benign-cli":
        raw_bytes = SyntheticPEBuilder.create_minimal_pe(
            custom_strings=["Benign Calculator CLI Tool v1.0", "GetStdHandle", "WriteFile", "ExitProcess", "Copyright 2026 Defensive Lab"]
        )
    elif sample_id == "lab-02-packed-upx":
        raw_bytes = SyntheticPEBuilder.create_packed_pe()
    elif sample_id == "lab-03-crypto-dll":
        raw_bytes = SyntheticPEBuilder.create_minimal_pe(
            characteristics=0x2102,  # DLL flag | EXECUTABLE | 32BIT
            custom_strings=["crypto_defense_helper.dll", "DllMain", "BCryptGenRandom", "CryptAcquireContextA", "CryptEncrypt", "Exported_HashDigest"]
        )
    elif sample_id == "lab-04-suspicious-stager":
        raw_bytes = SyntheticPEBuilder.create_suspicious_import_pe()
    elif sample_id == "lab-05-ethio-cyber":
        raw_bytes = SyntheticPEBuilder.create_ethiopian_targeted_pe()
    else:
        raw_bytes = SyntheticPEBuilder.create_minimal_pe()

    # Execute full deterministic static analysis pipeline
    analysis_result = unified_pipeline_service.execute_pipeline(
        content=raw_bytes,
        filename=sample_meta.filename,
        language=lang,
        user_id=current_user.id
    )

    analysis_id = analysis_result.get("analysis_id") or analysis_result.get("sample_id")
    logger.info(f"Student '{current_user.username}' (ID: {current_user.id}) loaded safe educational lab sample '{sample_meta.filename}' (Analysis ID: {analysis_id})")

    return {
        "success": True,
        "message": f"Successfully initialized safe educational practice lab for '{sample_meta.title}'.",
        "sample_meta": sample_meta.model_dump(),
        "analysis_id": analysis_id,
        "analysis_data": analysis_result
    }


@router.get("/quizzes", response_model=List[QuizQuestion], summary="Retrieve interactive knowledge check quiz questions")
def get_quiz_questions(
    current_user: UserModel = Depends(get_current_user)
):
    """
    Returns randomized educational multiple-choice quiz questions without revealing correct answer keys.
    """
    questions: List[QuizQuestion] = []
    for q in QUIZ_QUESTION_BANK:
        questions.append(QuizQuestion(
            id=q["id"],
            topic=q["topic"],
            difficulty=q["difficulty"],
            question=q["question"],
            options=[QuizOption(id=opt["id"], text=opt["text"]) for opt in q["options"]],
            hint=q["hint"]
        ))
    return questions


@router.post("/quizzes/evaluate", response_model=QuizEvaluationResponse, summary="Evaluate student quiz answers and calculate mastery score")
def evaluate_quiz_submission(
    submission: QuizEvaluationRequest,
    current_user: UserModel = Depends(get_current_user)
):
    """
    Grades student answers, computes mastery percentage, and delivers comprehensive technical rationale for every question.
    """
    q_map = {q["id"]: q for q in QUIZ_QUESTION_BANK}
    results: List[QuestionResult] = []
    correct_count = 0

    for sub in submission.answers:
        q_data = q_map.get(sub.question_id)
        if not q_data:
            continue

        is_correct = (sub.selected_option_id.lower() == q_data["correct_id"].lower())
        if is_correct:
            correct_count += 1

        results.append(QuestionResult(
            question_id=sub.question_id,
            is_correct=is_correct,
            selected_option_id=sub.selected_option_id,
            correct_option_id=q_data["correct_id"],
            explanation=q_data["explanation"]
        ))

    total = len(results) if results else len(QUIZ_QUESTION_BANK)
    score_pct = round((correct_count / total * 100.0), 1) if total > 0 else 0.0

    logger.info(f"Student '{current_user.username}' completed quiz evaluation: {correct_count}/{total} correct ({score_pct}%)")

    return QuizEvaluationResponse(
        total_questions=total,
        correct_count=correct_count,
        score_percentage=score_pct,
        passed=(score_pct >= 70.0),
        results=results
    )
