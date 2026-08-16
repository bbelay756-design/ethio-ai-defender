"""
Cybersecurity Educational Knowledge Base & Topics Module

Contains structured educational concepts for cybersecurity students across 14 core reverse-engineering topics:
1. PE format
2. DOS header
3. PE header
4. Sections
5. Entry point
6. Imports
7. Windows APIs
8. Strings
9. Entropy
10. Packing
11. Obfuscation
12. Static analysis
13. Reverse engineering
14. Threat indicators

Supports both Beginner and Advanced depth levels in English ('en') and Amharic ('am').
"""

from typing import Dict, List, Any


EDUCATIONAL_TOPICS_DATABASE: Dict[str, Dict[str, Any]] = {
    "PE_FORMAT": {
        "title": "Portable Executable (PE) Format",
        "category": "PE format",
        "en": {
            "what_is_it": "The Portable Executable (PE) format is the standard file structure used by 32-bit and 64-bit Windows operating systems for executables (.exe), DLL libraries (.dll), and device drivers (.sys).",
            "why_it_matters": "Understanding PE headers allows security analysts to examine how Windows parses, loads, and maps binary code into process virtual memory without running the file.",
            "proves_malicious": "No. The PE format alone does not prove malicious behavior. It is used by virtually all standard Windows software, both benign and malicious.",
            "what_to_learn_next": [
                "Explore the relationship between Relative Virtual Address (RVA) and Raw File Offsets.",
                "Learn how the Windows PE loader maps sections into virtual memory pages."
            ],
            "beginner_explanation": "Think of the PE format like the table of contents and layout of a book. It tells Windows where code, pictures, icons, and text are stored inside the file.",
            "advanced_explanation": "The PE architecture utilizes MS-DOS stub compatibility leading to the IMAGE_NT_HEADERS, containing COFF File Headers and Optional Headers (ImageBase, AddressOfEntryPoint, Subsystem, DataDirectory)."
        },
        "am": {
            "what_is_it": "የ Portable Executable (PE) ፎርማት በ 32-bit እና 64-bit Windows ኦፕሬቲንግ ሲስተም ለ Executables (.exe), DLLs እና Drivers የሚያገለግል መደበኛ የፋይል መዋቅር ነው።",
            "why_it_matters": "የ PE headers አደረጃጀትን መረዳት የሳይበር ተመራማሪዎች ፋይሉ ሳይከፈት Windows እንዴት ወደ Virtual Memory እንደሚጭነው እንዲተነትኑ ያስችላቸዋል።",
            "proves_malicious": "አያረጋግጥም። ይህ መዋቅር ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የ Relative Virtual Address (RVA) እና የ Raw File Offset ልዩነትን ማጥናት።",
                "የ Windows PE loader ፋይሎችን ወደ ማህደረ-ትውስታ (Memory) እንዴት እንደሚጭን መመርመር።"
            ],
            "beginner_explanation": "PE format ልክ እንደ መጽሐፍ ማውጫ ነው። ለ Windows የትኛው ክፍል ኮድ፣ የትኛው ጽሁፍ ወይም ምስል እንደሆነ ይነግረዋል።",
            "advanced_explanation": "የ PE መዋቅር ከ DOS MZ header ተነስቶ ወደ IMAGE_NT_HEADERS ይሸጋገራል፤ ይህም ImageBase፣ AddressOfEntryPoint እና DataDirectory ያካትታል።"
        }
    },
    "DOS_HEADER": {
        "title": "DOS Header & MZ Stub",
        "category": "DOS header",
        "en": {
            "what_is_it": "The 64-byte legacy MS-DOS header at the very beginning of every PE binary, starting with the magic ASCII signature 'MZ' (0x4D 0x5A) named after Mark Zbikowski.",
            "why_it_matters": "It contains the vital offset pointer 'e_lfanew' at offset 0x3C, which points directly to the real PE NT Header.",
            "proves_malicious": "No. The DOS header alone does not prove malicious behavior. Every valid Windows executable contains a DOS header for backward compatibility.",
            "what_to_learn_next": [
                "Inspect offset 0x3C in a hex editor to locate the PE NT header offset.",
                "Learn how the DOS stub message 'This program cannot be run in DOS mode' is stored."
            ],
            "beginner_explanation": "The DOS header is like an antique stamp on an envelope that proves to Windows this is a real Windows program.",
            "advanced_explanation": "The IMAGE_DOS_HEADER structure spans 64 bytes. Offsets 0x00 ('e_magic') and 0x3C ('e_lfanew') are strictly checked by the Windows PE loader."
        },
        "am": {
            "what_is_it": "በእያንዳንዱ የ PE ፋይል መጀመሪያ ላይ የሚገኝ 64-byte የ MS-DOS header ሲሆን፣ በ 'MZ' (0x4D 0x5A) ፊርማ ይጀምራል።",
            "why_it_matters": "በ offset 0x3C ላይ የሚገኘው 'e_lfanew' ፖይንተር ወደ ዋናው PE NT Header የሚያመላክት ወሳኝ መረጃ ይዟል።",
            "proves_malicious": "አያረጋግጥም። ይህ header ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "በ Hex Editor ውስጥ offset 0x3C ን በመመልከት የ PE NT Header መገኛን መፈለግ።",
                "የ DOS stub 'This program cannot be run in DOS mode' መልእክት እንዴት እንደሚቀመጥ ማየት።"
            ],
            "beginner_explanation": "DOS header ልክ እንደ መግቢያ ማህተም ነው። ለ Windows ይህ ፋይል እውነተኛ የኮምፒውተር ፕሮግራም መሆኑን ያሳውቃል።",
            "advanced_explanation": "የ IMAGE_DOS_HEADER መዋቅር 64 ባይት ሲሆን፣ e_magic እና e_lfanew በ loader በጥብቅ የሚፈተሹ ቁልፍ መስኮች ናቸው።"
        }
    },
    "PE_HEADER": {
        "title": "PE NT Headers & Optional Header",
        "category": "PE header",
        "en": {
            "what_is_it": "The core control header of a Windows binary, consisting of the 'PE\\0\\0' signature, COFF File Header, and the Optional Header.",
            "why_it_matters": "Defines target CPU architecture (x86, x64, ARM), compile timestamp, Subsystem (GUI vs Console), and security flags like ASLR and DEP.",
            "proves_malicious": "No. The PE header alone does not prove malicious behavior. All Windows PE executables require valid NT and Optional Headers to execute.",
            "what_to_learn_next": [
                "Understand DllCharacteristics flags (NX_COMPAT for DEP, DYNAMIC_BASE for ASLR).",
                "Learn how Subsystem values differentiate CLI tools from GUI applications."
            ],
            "beginner_explanation": "The PE header tells your computer which processor (like 32-bit or 64-bit) can run the program and whether it has a visual window.",
            "advanced_explanation": "IMAGE_NT_HEADERS contains IMAGE_FILE_HEADER (Machine architecture, NumberOfSections, TimeDateStamp) and IMAGE_OPTIONAL_HEADER (AddressOfEntryPoint, ImageBase, Subsystem)."
        },
        "am": {
            "what_is_it": "የ Windows ፋይል ዋና የቁጥጥር header ሲሆን የ 'PE\\0\\0' ፊርማን፣ COFF File Header እና Optional Header ያካትታል።",
            "why_it_matters": "የኮምፒውተሩን CPU አይነት (x86, x64, ARM)፣ የተፈበረከበትን ሰዓት እና እንደ ASLR/DEP ያሉ የደህንነት መከላከያዎችን ይገልጻል።",
            "proves_malicious": "አያረጋግጥም። ይህ header ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የ DllCharacteristics ባንዲራዎችን (DEP እና ASLR) መረዳት።",
                "የ Subsystem ልዩነቶችን (GUI ከ Console) መለየት።"
            ],
            "beginner_explanation": "PE header ኮምፒውተሩ የትኛው ፕሮሰሰር (32-bit ወይስ 64-bit) ፕሮግራሙን እንደሚያስኬደው ይነግረዋል።",
            "advanced_explanation": "IMAGE_NT_HEADERS የ Machine architecture፣ NumberOfSections፣ AddressOfEntryPoint እና Subsystem መረጃዎችን ይዟል።"
        }
    },
    "SECTIONS": {
        "title": "PE Memory Sections & Permissions",
        "category": "Sections",
        "en": {
            "what_is_it": "Containers inside a PE file that group code (.text), read-only data (.rdata), writable variables (.data), resources (.rsrc), or relocations (.reloc).",
            "why_it_matters": "Each section has memory access permissions (Readable, Writable, Executable). Violations of W^X (Write XOR Execute) warrant investigation.",
            "proves_malicious": "No. Unusual sections alone do not prove malicious behavior. Even unusual section permissions can occur in legitimate just-in-time compilers or protectors.",
            "what_to_learn_next": [
                "Learn the standard memory characteristics flags (IMAGE_SCN_MEM_READ, WRITE, EXECUTE).",
                "Understand why Virtual Size can legitimately differ from Raw Size on disk."
            ],
            "beginner_explanation": "Sections are like labeled folders inside a file: one folder holds the program instructions, another holds pictures and buttons, and another holds text.",
            "advanced_explanation": "IMAGE_SECTION_HEADER defines VirtualAddress, Misc.VirtualSize, SizeOfRawData, and Characteristics. Simultaneous write+execute flags violate standard defensive W^X policies."
        },
        "am": {
            "what_is_it": "የ PE ፋይል ክፍሎች ሲሆኑ ኮድ (.text)፣ ቋሚ መረጃ (.rdata)፣ ተለዋዋጭ ዳታ (.data) እና ምስሎችን (.rsrc) ይይዛሉ።",
            "why_it_matters": "እያንዳንዱ ክፍል የማንበብ (Read)፣ የመጻፍ (Write) እና የማስፈጸም (Execute) ፈቃድ አለው።",
            "proves_malicious": "አያረጋግጥም። ይህ የ section መዋቅር ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የ Section characteristics ፈቃዶችን (READ, WRITE, EXECUTE) ማጥናት።",
                "የ Virtual Size እና Raw Size ልዩነት ምን ማለት እንደሆነ መረዳት።"
            ],
            "beginner_explanation": "Sections ልክ እንደተከፋፈሉ ፎልደሮች ናቸው፡ አንዱ የኮድ ክፍል፣ ሌላው የጽሁፍ እና የምስል ማከማቻ ነው።",
            "advanced_explanation": "IMAGE_SECTION_HEADER የ VirtualSize፣ SizeOfRawData እና Characteristics ፈቃዶችን ይገልጻል።"
        }
    },
    "ENTRY_POINT": {
        "title": "Address of Entry Point (EP)",
        "category": "Entry point",
        "en": {
            "what_is_it": "The Relative Virtual Address (RVA) where CPU execution begins once the operating system loads the binary into memory.",
            "why_it_matters": "In standard executables, the entry point typically lands in the .text section. In packed or obfuscated files, it often points to a staging or decryption stub in the last section.",
            "proves_malicious": "No. An unusual entry point alone does not prove malicious behavior. Non-standard entry points are frequently used by packers and game security engines.",
            "what_to_learn_next": [
                "Trace from the PE Entry Point to the C runtime startup routine (mainCRTStartup/WinMainCRTStartup).",
                "Analyze how TLS (Thread Local Storage) callbacks can execute code before the Entry Point."
            ],
            "beginner_explanation": "The entry point is the very first instruction line where the computer starts reading and executing the program.",
            "advanced_explanation": "AddressOfEntryPoint in IMAGE_OPTIONAL_HEADER is added to ImageBase to determine the initial EIP/RIP register address on thread creation."
        },
        "am": {
            "what_is_it": "ኦፕሬቲንግ ሲስተሙ ፋይሉን ወደ ማህደረ-ትውስታ ከጫነ በኋላ የ CPU ማስፈጸሚያ የሚጀምርበት የመጀመሪያ አድራሻ (RVA) ነው።",
            "why_it_matters": "በመደበኛ ፕሮግራሞች የመግቢያ አድራሻው በ .text ክፍል ውስጥ ይገኛል። በታሸጉ (Packed) ፋይሎች ውስጥ ግን ወደ መፍቻ ስክሪፕት ሊያመላክት ይችላል።",
            "proves_malicious": "አያረጋግጥም። የመግቢያ አድራሻ ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "ከ Entry Point ተነስቶ ወደ mainCRTStartup የመነሻ ኮድ መጓዝን ማጥናት።",
                "የ TLS Callbacks ኮድ ከ Entry Point በፊት እንዴት እንደሚሰራ መረዳት።"
            ],
            "beginner_explanation": "Entry point ኮምፒውተሩ ፕሮግራሙን ማንበብ እና ማስኬድ የሚጀምርበት የመጀመሪያው መስመር ነው።",
            "advanced_explanation": "በ IMAGE_OPTIONAL_HEADER ውስጥ ያለው AddressOfEntryPoint ከ ImageBase ጋር ተደምሮ የመነሻ EIP/RIP ሬጅስተርን ይወስናል።"
        }
    },
    "IMPORTS": {
        "title": "Import Address Table (IAT) & Dynamic Linking",
        "category": "Imports",
        "en": {
            "what_is_it": "The Import Table lists external functions and Dynamic Link Libraries (DLLs) requested by the binary from Windows (e.g. KERNEL32.dll, USER32.dll).",
            "why_it_matters": "Reveals the static technical capabilities of the executable without running it (e.g., file handling, network sockets, memory allocation).",
            "proves_malicious": "No. Imported functions alone do not prove malicious behavior. Windows applications rely heavily on imported APIs for standard operating system interaction.",
            "what_to_learn_next": [
                "Learn how the Import Address Table (IAT) is resolved at runtime by the loader.",
                "Understand dynamic API resolution via LoadLibraryA and GetProcAddress."
            ],
            "beginner_explanation": "Imports are like a list of phone numbers the program calls to ask Windows to open a file, display a message, or connect to the internet.",
            "advanced_explanation": "The IMAGE_DIRECTORY_ENTRY_IMPORT points to IMAGE_IMPORT_DESCRIPTOR structures containing OriginalFirstThunk (INT) and FirstThunk (IAT)."
        },
        "am": {
            "what_is_it": "ፕሮግራሙ ከ Windows ሲስተም የሚጠይቃቸውን የውጭ DLL ላይብረሪዎች እና የ API ፈንክሽኖች ዝርዝር የያዘ ሰንጠረዥ ነው።",
            "why_it_matters": "ፋይሉ ሳይሰራ የቴክኒክ አቅሙን (የፋይል፣ የኔትወርክ፣ የማህደረ-ትውስታ ስራዎችን) ለመረዳት ይረዳል።",
            "proves_malicious": "አያረጋግጥም። ይህ የ Imports ሰንጠረዥ ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የ Import Address Table (IAT) በ runtime እንዴት እንደሚሞላ ማጥናት።",
                "የ LoadLibraryA እና GetProcAddress የ dynamic API ጥሪዎችን መረዳት።"
            ],
            "beginner_explanation": "Imports ፕሮግራሙ ፋይል ለመክፈት ወይም መልእክት ለማሳየት ከ Windows የሚጠይቃቸው የእርዳታ ፈንክሽኖች ናቸው።",
            "advanced_explanation": "IMAGE_DIRECTORY_ENTRY_IMPORT ወደ IMAGE_IMPORT_DESCRIPTOR ይመራል፤ ይህም INT እና IAT ሰንጠረዦችን ያካትታል።"
        }
    },
    "WINDOWS_APIS": {
        "title": "Windows API Categorization & Risk Relevance",
        "category": "Windows APIs",
        "en": {
            "what_is_it": "Documented OS system calls provided by Microsoft Windows across functional subsystems (FILE, PROCESS, MEMORY, NETWORK, REGISTRY, SERVICE, CRYPTO).",
            "why_it_matters": "Categorizing APIs helps analysts identify functional primitives (e.g., VirtualAlloc for memory, CreateProcess for process launching).",
            "proves_malicious": "No. This API alone does not prove malicious behavior. Legitimate utilities invoke the same APIs for normal tasks.",
            "what_to_learn_next": [
                "Study correlated API combinations (e.g. OpenProcess + CreateRemoteThread).",
                "Learn how Windows native system calls (Nt/Zw syscalls) bypass user-mode API hooks."
            ],
            "beginner_explanation": "Windows APIs are standard building blocks provided by Microsoft so programs can interact safely with your hardware and system.",
            "advanced_explanation": "APIs like VirtualProtect alter page permissions (e.g. PAGE_EXECUTE_READWRITE). While essential for JIT compilers, they are also monitored during static triage for dynamic code unpacking."
        },
        "am": {
            "what_is_it": "በ Microsoft Windows የሚሰጡ የስርዓት ጥሪዎች (System Calls) ሲሆኑ በ 11 ዘርፎች (FILE, PROCESS, MEMORY, NETWORK, ወዘተ) ይከፈላሉ።",
            "why_it_matters": "የ API ፈንክሽኖችን መመደብ የፋይሉን ቴክኒካዊ ችሎታ በቀላሉ ለመለየት ያስችላል።",
            "proves_malicious": "አያረጋግጥም። ይህ API ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "ተዛማጅ የ API ጥንዶችን (ምሳሌ: OpenProcess + CreateRemoteThread) መመርመር።",
                "የ Windows Native System Calls (Nt/Zw) እንዴት እንደሚሰሩ ማጥናት።"
            ],
            "beginner_explanation": "Windows APIs ፕሮግራሞች ከኮምፒውተሩ ጋር በሰላም እንዲነጋገሩ የተሰሩ ዝግጁ መመሪያዎች ናቸው።",
            "advanced_explanation": "እንደ VirtualProtect ያሉ APIs የማህደረ-ትውስታ ገጽ ፈቃድን ይቀይራሉ። ለ JIT compilers ጠቃሚ ሲሆኑ ለ code unpacking ትንተናም ይመረመራሉ።"
        }
    },
    "STRINGS": {
        "title": "Static String Extraction (ASCII & UTF-16LE Unicode)",
        "category": "Strings",
        "en": {
            "what_is_it": "Sequences of printable characters (ASCII 8-bit or Unicode 16-bit) embedded directly within the compiled binary data.",
            "why_it_matters": "Extracts human-readable clues such as URLs, IP addresses, registry keys, error logs, and referenced DLLs.",
            "proves_malicious": "No. Extracted strings alone do not prove malicious behavior. Strings containing keywords or URLs are common across legitimate software.",
            "what_to_learn_next": [
                "Learn string decoding techniques (XOR, Base64, RC4) for obfuscated strings.",
                "Understand why advanced malware hides strings using stack strings or hashing."
            ],
            "beginner_explanation": "Strings are text snippets written inside the program, like website links, error messages, or folder paths.",
            "advanced_explanation": "Static string analysis scans for contiguous printable byte runs (min length 4). Contextual classification categorizes strings into URLs, IPs, registry paths, and commands."
        },
        "am": {
            "what_is_it": "በተጠናቀረው የፋይል ዳታ ውስጥ የሚገኙ የሚነበቡ የ ASCII (8-bit) እና Unicode (16-bit) የጽሁፍ ቅደም ተከተሎች ናቸው።",
            "why_it_matters": "እንደ የድረ-ገጽ አድራሻ (URL)፣ IP፣ የ Registry መንገዶች እና የፋይል ስሞችን በቀላሉ ለማግኘት ይጠቅማል።",
            "proves_malicious": "አያረጋግጥም። የተገኙ ጽሁፎች ብቻቸውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆኑ አይችሉም።",
            "what_to_learn_next": [
                "የተደበቁ ጽሁፎችን (XOR, Base64) የመፍታት ቴክኒኮችን ማጥናት።",
                "የላቁ ማልዌሮች ጽሁፍን በ Stack Strings እንዴት እንደሚደብቁ መረዳት።"
            ],
            "beginner_explanation": "Strings በፋይሉ ውስጥ የተጻፉ እንደ የዌብሳይት አድራሻዎች ወይም የስህተት መልእክቶች ያሉ ጽሁፎች ናቸው።",
            "advanced_explanation": "የ Static string ትንተና ተከታታይ የሚነበቡ ባይቶችን ይፈልጋል እንዲሁም በ URLs, IPs, Registry እና Commands ዘርፍ ይከፍላቸዋል።"
        }
    },
    "ENTROPY": {
        "title": "Shannon Entropy & Randomness Measurement",
        "category": "Entropy",
        "en": {
            "what_is_it": "A mathematical formula H(X) = -sum(p * log2(p)) calculating information density and randomness on a scale from 0.0 to 8.0.",
            "why_it_matters": "High entropy (> 7.2) indicates compressed data, encrypted payloads, or software packing.",
            "proves_malicious": "No. High entropy alone does not prove malicious behavior. It is completely normal for compressed media (PNG/MP3/ZIP), encrypted assets, and software installers.",
            "what_to_learn_next": [
                "Calculate entropy per section to identify which specific section contains dense payload code.",
                "Learn how to distinguish standard zlib/gzip compression from custom encryption."
            ],
            "beginner_explanation": "Entropy measures how crowded and jumbled data is. Plain text has low entropy; encrypted or zipped files have very high entropy.",
            "advanced_explanation": "Shannon entropy quantifies average bits of uncertainty per byte. In PE analysis, section entropy is correlated with raw-to-virtual size ratios to detect packing."
        },
        "am": {
            "what_is_it": "የመረጃን ድብልቅነት እና እፍጋት ከ 0.0 እስከ 8.0 በሚደርስ የሂሳብ ቀመር H(X) = -sum(p * log2(p)) የሚለካ ስሌት ነው።",
            "why_it_matters": "ከፍተኛ Entropy (> 7.2) የታመቀ (Compressed) ወይም የተመሰጠረ (Encrypted) ዳታ መኖሩን ያመለክታል።",
            "proves_malicious": "አያረጋግጥም። ከፍተኛ Entropy ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የእያንዳንዱን section entropy ለይቶ በማስላት የታመቀውን ክፍል ማግኘት።",
                "በመደበኛ compression እና በ encryption መካከል ያለውን ልዩነት መረዳት።"
            ],
            "beginner_explanation": "Entropy ዳታው ምን ያህል የተዘበራረቀ እና የታመቀ እንደሆነ ይለካል፤ የተመሰጠሩ ወይም ዚፕ የተደረጉ ፋይሎች ከፍተኛ Entropy አላቸው።",
            "advanced_explanation": "የ Shannon entropy በአንድ ባይት ውስጥ ያለውን የመረጃ እርግጠኛ-አልባነት ይለካል። በ PE ትንተና ከ section sizes ጋር ተቀናጅቶ packing ን ለመለየት ይረዳል።"
        }
    },
    "PACKING": {
        "title": "Software Packing & Runtime Unpackers",
        "category": "Packing",
        "en": {
            "what_is_it": "The process of compressing or encrypting an executable's original code and adding an unpacking stub that reconstructs it in memory at runtime.",
            "why_it_matters": "Hides original code and imports from simple static inspection tools.",
            "proves_malicious": "No. Software packing alone does not prove malicious behavior. Commercial software protectors and game DRM heavily utilize packing to protect intellectual property.",
            "what_to_learn_next": [
                "Learn how to set a breakpoint on the Original Entry Point (OEP) in a debugger.",
                "Use memory dumping tools (e.g. Scylla / Process Dump) to dump unpacked binaries."
            ],
            "beginner_explanation": "Packing is like putting a computer program inside a zipped briefcase that automatically unzips itself in memory when opened.",
            "advanced_explanation": "Packed PEs typically exhibit high entropy in non-standard sections, minimal initial import tables (only LoadLibraryA/GetProcAddress), and zero raw size allocations."
        },
        "am": {
            "what_is_it": "ዋናውን የፕሮግራም ኮድ አምቆ ወይም አመሳጥሮ በማስቀመጥ ፋይሉ ሲከፈት በማህደረ-ትውስታ ውስጥ መልሶ የሚፈታበት ቴክኖሎጂ ነው።",
            "why_it_matters": "ዋናውን ኮድ እና Imports ከቀጥታ static ትንተና ይደብቃል።",
            "proves_malicious": "አያረጋግጥም። የታሸገ (Packed) ፋይል ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "በ Debugger ውስጥ ዋናውን Original Entry Point (OEP) የማግኛ ዘዴዎችን መማር።",
                "የ Memory dumping መሳሪያዎችን በመጠቀም የተፈታውን ኮድ ማስቀረት።"
            ],
            "beginner_explanation": "Packing ልክ ፕሮግራሙን በዚፕ ሻንጣ ውስጥ አስቀምጦ ሲከፈት ራሱ ፈትቶ እንዲሰራ እንደማድረግ ነው።",
            "advanced_explanation": "የታሸጉ PE ፋይሎች ከፍተኛ entropy፣ በጣም ጥቂት የመጀመሪያ imports እና በ sections መካከል የ size ልዩነት ያሳያሉ።"
        }
    },
    "OBFUSCATION": {
        "title": "Code & String Obfuscation Techniques",
        "category": "Obfuscation",
        "en": {
            "what_is_it": "Techniques that make source or binary code deliberately difficult for human analysts and automated tools to understand.",
            "why_it_matters": "Slows down reverse engineering by hiding control flow, renaming symbols, and scrambling string constants.",
            "proves_malicious": "No. Code obfuscation alone does not prove malicious behavior. Obfuscators are widely utilized by legitimate commercial software vendors to protect proprietary algorithms.",
            "what_to_learn_next": [
                "Study control flow flattening and dead code insertion deobfuscation.",
                "Write automated scripts (IDAPython/Ghidra) to decrypt obfuscated strings."
            ],
            "beginner_explanation": "Obfuscation is like writing a message in secret code so that someone glancing at it cannot easily read what it does.",
            "advanced_explanation": "Techniques include instruction substitution, opaque predicates, anti-disassembly tricks, and dynamic API resolving to defeat static disassemblers."
        },
        "am": {
            "what_is_it": "የኮምፒውተር ኮድን ሆነ ተብሎ ለሰውም ሆነ ለመመርመሪያ መሳሪያዎች በቀላሉ እንዳይገባ አድርጎ የማወሳሰብ ቴክኒክ ነው።",
            "why_it_matters": "የ Reverse engineering ስራን ለማዘግየት፣ የኮዱን ፍሰት ለመደበቅ እና ጽሁፎችን ለማዛባት ይጠቅማል።",
            "proves_malicious": "አያረጋግጥም። የተወሳሰበ ኮድ (Obfuscation) ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የተወሳሰበ የኮድ ፍሰትን (Control Flow) የማስተካከል ዘዴዎችን ማጥናት።",
                "በ Python ስክሪፕት አማካኝነት የተደበቁ ጽሁፎችን መፍታት።"
            ],
            "beginner_explanation": "Obfuscation ልክ መልእክትን በሚስጥር ቋንቋ በመጻፍ በቀላሉ እንዳይነበብ የማድረግ ዘዴ ነው።",
            "advanced_explanation": "ይህም opaque predicates፣ anti-disassembly ቴክኒኮችን እና dynamic API resolving ን ያካትታል።"
        }
    },
    "STATIC_ANALYSIS": {
        "title": "Deterministic Static Malware Analysis",
        "category": "Static analysis",
        "en": {
            "what_is_it": "The practice of examining binary headers, structures, strings, and disassemblies without executing the target file.",
            "why_it_matters": "Provides a safe, reproducible baseline triage methodology with zero risk of malware infection or lateral spread.",
            "proves_malicious": "No. Static analysis alone does not prove malicious behavior. It observes technical structural capability, not confirmed malicious intent.",
            "what_to_learn_next": [
                "Combine static analysis triage with sandboxed dynamic behavioral monitoring.",
                "Learn how to author YARA detection rules based on verified static artifacts."
            ],
            "beginner_explanation": "Static analysis is like reading a recipe book without cooking the food: you look at the ingredients and steps safely without making a mess.",
            "advanced_explanation": "Static analysis leverages deterministic parsing of PE structures, Shannon entropy, IAT imports, and cryptographic hashing (SHA-256) under complete isolation."
        },
        "am": {
            "what_is_it": "ፋይሉን ወደ ስራ ሳያስገቡ የፋይሉን headers፣ ዳታ፣ ጽሁፎች እና መዋቅር በደህና ሁኔታ የመመርመር ሳይንስ ነው።",
            "why_it_matters": "ምንም አይነት የኢንፌክሽን ወይም የጥቃት ስጋት ሳይኖር የፋይሉን ይዘት በሰላማዊ መንገድ ለመረዳት ያስችላል።",
            "proves_malicious": "አያረጋግጥም። Static analysis ብቻውን የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የ Static analysis ውጤትን ከተከለለ የ Dynamic sandbox ክትትል ጋር ማቀናጀት።",
                "የተገኙ static መረጃዎችን ተጠቅሞ የ YARA ህጎችን መጻፍ።"
            ],
            "beginner_explanation": "Static analysis ልክ የኬክ አሰራር መጽሐፍን ከማንበብ ጋር ይመሳሰላል፡ ኬኩን ሳንጋግር ንጥረ-ነገሮቹን በሙሉ በደህና ሁኔታ እናውቃለን።",
            "advanced_explanation": "ይህ ዘዴ የ PE አደረጃጀትን፣ የ Shannon entropy፣ IAT imports እና SHA-256 ሃሾችን ያለ ምንም ማስፈጸሚያ ይተነትናል።"
        }
    },
    "REVERSE_ENGINEERING": {
        "title": "Defensive Reverse Engineering & Disassembly",
        "category": "Reverse engineering",
        "en": {
            "what_is_it": "The process of deconstructing compiled machine code back into assembly instructions or high-level pseudo-code (C/C++) to understand its logic.",
            "why_it_matters": "Enables analysts to discover hidden capabilities, cryptographic keys, vulnerability flaws, and protocol specifications.",
            "proves_malicious": "No. Reverse engineering alone does not prove malicious behavior. It is an analytical discipline utilized for interoperability, security auditing, and malware analysis.",
            "what_to_learn_next": [
                "Learn x86/x64 assembly instructions (MOV, PUSH, POP, CALL, JMP, LEA).",
                "Practice using open-source disassemblers like Ghidra and IDA Free."
            ],
            "beginner_explanation": "Reverse engineering is like taking apart a mechanical clock piece by piece to see exactly how the gears and springs make it tick.",
            "advanced_explanation": "Disassemblers translate opcode bytes into x86/x64 mnemonic assembly. Decompilers construct Abstract Syntax Trees (AST) to generate readable C pseudo-code."
        },
        "am": {
            "what_is_it": "የተጠናቀረ የማሽን ኮድን ወደ Assembly ወይም ወደ ከፍተኛ የፕሮግራሚንግ ቋንቋ (C/C++) በመቀየር የፋይሉን አሰራር የመረዳት ሳይንስ ነው።",
            "why_it_matters": "የተደበቁ ቴክኒካዊ ችሎታዎችን፣ የደህንነት ክፍተቶችን እና የፕሮቶኮል አሰራርን ለመመርመር ያስችላል።",
            "proves_malicious": "አያረጋግጥም። ይህ የጥናት ሂደት ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            "what_to_learn_next": [
                "የ x86/x64 Assembly መመሪያዎችን (MOV, PUSH, POP, CALL, LEA) መማር።",
                "እንደ Ghidra ባሉ ክፍት የዲሳሰምብሊ መሳሪያዎች ልምምድ ማድረግ።"
            ],
            "beginner_explanation": "Reverse engineering ልክ አንድን ሰዓት ፈትቶ ውስጡ ያሉትን እቃዎች እና አሰራሩን እንደማየት ነው።",
            "advanced_explanation": "ዲሳሰምብለሮች የማሽን ባይቶችን ወደ x86/x64 Assembly ሲቀይሩ፣ ዲኮምፓይለሮች ደግሞ ወደ C ቋንቋ ይቀይሯቸዋል።"
        }
    },
    "THREAT_INDICATORS": {
        "title": "Correlated Threat Indicators & Heuristic Analysis",
        "category": "Threat indicators",
        "en": {
            "what_is_it": "Patterns of correlated technical evidence across multiple binary features (e.g., sections + entropy + imports) that suggest potential security relevance.",
            "why_it_matters": "Avoids naive single-feature false alarms by requiring complementary evidence before flagging elevated risk.",
            "proves_malicious": "No. Threat indicators alone do not prove malicious behavior. Indicators represent technical patterns worth investigating, not confirmed maliciousness.",
            "what_to_learn_next": [
                "Study MITRE ATT&CK techniques mapped to static indicators.",
                "Learn how Security Operations Centers (SOC) triage indicators using SIEM and EDR."
            ],
            "beginner_explanation": "Threat indicators are like clues in a detective story: finding one clue isn't enough, but finding five matching clues tells you where to investigate.",
            "advanced_explanation": "Heuristic engines correlate multi-dimensional signals (e.g. W+X sections + high entropy + VirtualAlloc + OpenProcess) to calculate explainable threat scores."
        },
        "am": {
            "what_is_it": "በተለያዩ የፋይል ክፍሎች (sections, entropy, imports) የተገኙ የተዛመዱ ቴክኒካዊ መረጃዎች ጥምረት ነው።",
            "why_it_matters": "በአንድ ነጠላ መረጃ ብቻ የሚከሰቱ የተሳሳቱ ድምዳሜዎችን (False Positives) በማስቀረት ትክክለኛ የጥናት አቅጣጫን ያሳያል።",
            "proves_malicious": "አያረጋግጥም። አመልካቾች ብቻቸውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆኑ አይችሉም።",
            "what_to_learn_next": [
                "የ MITRE ATT&CK ስልቶችን ከአመልካቾች ጋር ማዛመድን መማር።",
                "የ SOC ባለሙያዎች አመልካቾችን በ SIEM እንዴት እንደሚከታተሉ መረዳት።"
            ],
            "beginner_explanation": "Threat indicators ልክ እንደ መርማሪ ፍንጮች ናቸው፤ አንድ ፍንጭ ብቻውን በቂ ባይሆንም በርካታ ፍንጮች ሲሰበሰቡ ትክክለኛውን ቦታ ለማየት ይረዳሉ።",
            "advanced_explanation": "Heuristic ሞተሮች የተለያዩ ቴክኒካዊ መረጃዎችን በማቀናጀት ሊብራራ የሚችል የስጋት ውጤት ያሰላሉ።"
        }
    }
}
