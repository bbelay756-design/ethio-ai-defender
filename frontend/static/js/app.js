/**

 * ETHIO-AI DEFENDER - DEFENSIVE SECURITY DASHBOARD CONTROLLER

 * Handles tab navigation, dual-language localization (EN/AM),

 * sample upload & live rendering across all 8 views.

 */



// Application State (Authentication States: AUTHENTICATED, UNAUTHENTICATED, AUTHENTICATION_LOADING)

const state = {

    authStatus: 'AUTHENTICATION_LOADING',

    currentLanguage: 'en',

    currentDifficulty: 'BEGINNER',

    currentTab: 'public',

    sampleData: null,

    activeAnalysisId: null,

    user: null,

    token: localStorage.getItem('ethio_auth_token') || null,

};



// Bilingual Translation Dictionary (English & Amharic)

const I18N = {

    en: {

        nav_home: "Home",

        nav_analysis: "Analysis Overview",

        nav_pe: "PE Analysis",

        nav_imports: "Imports & APIs",

        nav_strings: "Strings",

        nav_indicators: "Suspicious Indicators",

        nav_ai: "AI Security Analyst",

        nav_learning: "Learning Center",

        nav_admin: "Admin & Users",

        btn_signin: "Sign In",

        tab_signin: "Sign In",

        tab_register: "Register",

        lbl_username: "Username",

        lbl_email: "Email",

        lbl_password: "Password",

        lbl_desired_role: "Role",

        btn_login_submit: "Sign In",

        btn_register_submit: "Create Account",

        admin_title: "User Management & Access Control",

        admin_subtitle: "Administrator control for roles, credentials, and platform authorization.",

        btn_refresh_users: "Refresh Users",

        registered_users_table: "Registered Platform Users",

        engine_status: "Static Engine: Operational",

        non_exec_guarantee: "Zero-Execution Guarantee Enforced",

        home_title: "ETHIO-AI Defender",

        home_description: "Defensive static malware analysis and reverse-engineering platform designed for national cybersecurity resilience, SOC analysts, and university research laboratories.",

        upload_heading: "Upload Binary for Static Analysis",

        dropzone_title: "Drag and drop Windows PE executable here",

        dropzone_subtitle: "or click to browse local files",

        btn_choose_file: "Select .exe / .dll",

        or_try_demo: "Or test with safe synthetic sample:",

        btn_load_demo: "Load Demo Banking Agent",

        security_heading: "Perimeter & Security Policy",

        warning_title: "Strict Non-Execution Policy",

        warning_body: "Uploaded files are analyzed statically without runtime execution. Files are isolated in memory and quarantined on disk. Never execute untrusted binaries on host machines.",

        supported_formats: "Supported File Types:",

        max_size: "Max File Size:",

        analysis_scope: "Analysis Scope:",

        analysis_overview_title: "Analysis Overview & Threat Posture",

        analysis_overview_subtitle: "Cryptographic identity, architectural classification, and heuristic threat score.",

        lbl_filename: "Filename",

        lbl_arch: "Architecture",

        lbl_risk_level: "Risk Level",

        lbl_threat_score: "Threat Score",

        heuristic_metric: "Heuristic Analyst Metric",

        lbl_crypto_hashes: "Cryptographic Hashes",

        lbl_ethio_context: "Ethiopian Context Assessment",

        lbl_environment: "Target Environment:",

        lbl_relevance: "Sector Relevance:",

        lbl_context_reason: "Evaluation Context:",

        pe_analysis_title: "Portable Executable (PE) Structure",

        pe_analysis_subtitle: "DOS headers, NT optional headers, entry point, and memory section mapping.",

        lbl_pe_headers: "PE Header Parameters",

        lbl_entropy_summary: "Entropy & Anomaly Summary",

        lbl_sections_table: "PE Memory Sections Table",

        msg_no_sections: "No sections data available.",

        imports_title: "Windows API & DLL Imports",

        imports_subtitle: "Categorized external functions and technical capability primitives.",

        msg_no_imports: "No imported APIs detected.",

        strings_title: "Extracted Static Strings",

        strings_subtitle: "Classified ASCII and UTF-16LE Unicode sequences (URLs, IPs, Registry, Commands).",

        indicators_title: "Correlated Suspicious Indicators",

        indicators_subtitle: "Multi-feature heuristic correlations evaluated across headers, sections, and APIs.",

        msg_no_indicators: "No suspicious indicators detected for the current sample.",

        ai_analyst_title: "AI Security Analyst Assessment",

        ai_analyst_subtitle: "Grounded interpretation of deterministic static findings with privacy boundary protections.",

        ai_summary_head: "Executive Security Summary",

        ai_key_findings: "Key Findings",

        ai_benign_explanations: "Possible Benign Explanations",

        ai_recommended_investigation: "Recommended Investigation Steps",

        learning_title: "Cybersecurity Reverse-Engineering Learning Center",

        learning_subtitle: "Interactive reverse-engineering lessons for cybersecurity students and apprentices.",

        select_concept: "Explore a Concept",

        learn_what_is_it: "1. What is it?",

        learn_why_it_matters: "2. Why does it matter?",

        learn_explanation: "3. Explanation",

        learn_does_it_prove_malware: "4. Does it prove malicious behavior?",

        learn_what_next: "5. What should I learn next?",

    },

    am: {

        nav_home: "ßêÿßèÉßê╗ (Home)",

        nav_analysis: "ßï¿ßëÁßèòßë░ßèô ßèáßîáßëâßêïßï¡ ßèÑßï¡ßë│",

        nav_pe: "ßï¿ PE ßëÁßèòßë░ßèô",

        nav_imports: "ßï¿ßë░ßîáßê® APIs ßèÑßèô DLLs",

        nav_strings: "ßî¢ßêüßìÄßë¢ (Strings)",

        nav_indicators: "ßï¿ßêÁßîïßëÁ ßèáßêÿßêìßè½ßë¥ßë¢",

        nav_ai: "ßï¿ AI ßï░ßêàßèòßèÉßëÁ ßë░ßèòßë│ßèØ",

        nav_learning: "ßï¿ßê│ßï¡ßëáßê¡ ßï░ßêàßèòßèÉßëÁ ßëÁßêØßêàßê¡ßëÁ",

        nav_admin: "ßï¿ßèáßêÁßë░ßï│ßï│ßê¬ ßèÑßèô ßï¿ßë░ßîáßëâßêÜßïÄßë¢ ßêøßïòßè¿ßêì",

        btn_signin: "ßîìßëú (Sign In)",

        tab_signin: "ßîìßëú",

        tab_register: "ßë░ßêÿßïØßîêßëÑ",

        lbl_username: "ßï¿ßë░ßîáßëâßêÜ ßêÁßêØ",

        lbl_email: "ßèóßê£ßï¡ßêì",

        lbl_password: "ßï¿ßï¡ßêêßìì ßëâßêì",

        lbl_desired_role: "ßêÜßèô",

        btn_login_submit: "ßîìßëú",

        btn_register_submit: "ßêÿßêêßï½ ßììßîáßê¡",

        admin_title: "ßï¿ßë░ßîáßëâßêÜßïÄßë¢ ßèáßêÁßë░ßï│ßï░ßê¡ ßèÑßèô ßï¿ßìêßëâßïÁ ßëüßîÑßîÑßê¡",

        admin_subtitle: "ßï¿ßë░ßîáßëâßêÜßïÄßë¢ßèò ßêÜßèôßïÄßë¢ ßèÑßèô ßï¿ßììßëâßïÁ ßï░ßê¿ßîâßïÄßë¢ ßêÿßëåßîúßîáßê¬ßï½ßìó",

        btn_refresh_users: "ßïØßê¡ßïØßê®ßèò ßèáßïÁßêÁ",

        registered_users_table: "ßï¿ßë░ßêÿßïÿßîêßëí ßï¿ßêÿßïÁßê¿ßè® ßë░ßîáßëâßêÜßïÄßë¢",

        engine_status: "ßï¿ Static ßê×ßë░ßê¡ßìí ßïØßîìßîü ßèÉßïì",

        non_exec_guarantee: "ßìïßï¡ßêë ßê│ßï¡ßê░ßê½ ßï¿ßêÿßêÿßê¡ßêÿßê¡ ßïïßêÁßëÁßèô ßë░ßê¿ßîïßîìßîºßêì",

        home_title: "ßèóßëÁßï«-ßèáßï¡ßèáßï¡ ßï░ßêàßèòßèÉßëÁ (ETHIO-AI Defender)",

        home_description: "ßï¿ßêÇßîêßê½ßïè ßï¿ßê│ßï¡ßëáßê¡ ßï░ßêàßèòßèÉßëÁßèò ßêêßêøßîáßèôßè¿ßê¡ ßèÑßèô ßï¿ßë░ßîáßëâßêÜßïÄßë¢ßèò ßêÿßê¿ßîâ ßêêßêÿßîáßëáßëà ßï¿ßë░ßê░ßê½ ßï¿ PE ßìïßï¡ßêÄßë¢ static ßêÿßêÿßê¡ßêÿßê¬ßï½ ßèÑßèô ßï¿ Reverse Engineering ßêÁßê¡ßïôßëÁßìó",

        upload_heading: "ßìïßï¡ßêì ßêê Static ßëÁßèòßë░ßèô ßï½ßêÁßîêßëí",

        dropzone_title: "ßï¿ Windows PE ßìïßï¡ßêì ßèÑßïÜßêà ßï¡ßîÄßëÁßë▒ ßèÑßèô ßï¡ßêìßëÇßëü",

        dropzone_subtitle: "ßïêßï¡ßêØ ßè¿ßè«ßêØßìÆßïìßë░ßê¡ßïÄ ßêêßêÿßêØßê¿ßîÑ ßï¡ßî½ßèæ",

        btn_choose_file: "ßï¿ .exe / .dll ßìïßï¡ßêì ßï¡ßêØßê¿ßîí",

        or_try_demo: "ßïêßï¡ßêØ ßïØßîìßîü ßï¿ßêÖßè¿ßê½ ßèôßêÖßèô ßï¡ßîáßëÇßêÖßìí",

        btn_load_demo: "ßï¿ßêÖßè¿ßê½ ßï¿ßëúßèòßè¡ ßïêßè¬ßêì ßìïßï¡ßêì ßî½ßèò",

        security_heading: "ßï¿ßï░ßêàßèòßèÉßëÁ ßèÑßèô ßï¿ßîÑßëáßëâ ßìûßêèßê▓",

        warning_title: "ßìïßï¡ßêìßèò ßï½ßêêßêøßêÁßè¼ßïÁ ßîÑßëÑßëà ßìûßêèßê▓",

        warning_body: "ßï¿ßîêßëí ßìïßï¡ßêÄßë¢ ßê│ßï¡ßè¿ßìêßë▒ ßèÑßèô ßïêßï░ ßêÁßê½ ßê│ßï¡ßîêßëí ßëá static ßëÁßèòßë░ßèô ßëÑßë╗ ßï¡ßêÿßê¿ßêÿßê½ßêëßìó ßêøßèôßë©ßïìßèòßêØ ßèáßîáßê½ßîúßê¬ ßìïßï¡ßêÄßë¢ ßëáßïïßèôßïì ßè«ßêØßìÆßïìßë░ßê¡ ßêïßï¡ ßìêßî¢ßê× ßèÑßèòßï│ßï¡ßè¿ßììßë▒ßìó",

        supported_formats: "ßï¿ßêÜßï░ßîêßìë ßï¿ßìïßï¡ßêì ßèáßï¡ßèÉßëÂßë¢ßìí",

        max_size: "ßè¿ßììßë░ßèø ßï¿ßìïßï¡ßêì ßêÿßîáßèòßìí",

        analysis_scope: "ßï¿ßëÁßèòßë░ßèôßïì ßïêßê░ßèòßìí",

        analysis_overview_title: "ßï¿ßëÁßèòßë░ßèô ßèáßîáßëâßêïßï¡ ßèÑßï¡ßë│ ßèÑßèô ßï¿ßêÁßîïßëÁ ßï░ßê¿ßîâ",

        analysis_overview_subtitle: "ßï¿ßìïßï¡ßêë ßï¿ßêâßê¢ ßêøßèòßèÉßëÁßìú ßèáßê¡ßè¡ßë┤ßè¡ßë©ßê¡ ßèÑßèô ßï¿ Heuristic ßêÁßîïßëÁ ßïìßîñßëÁßìó",

        lbl_filename: "ßï¿ßìïßï¡ßêì ßêÁßêØ",

        lbl_arch: "ßèáßê¡ßè¡ßë┤ßè¡ßë©ßê¡",

        lbl_risk_level: "ßï¿ßêÁßîïßëÁ ßï░ßê¿ßîâ",

        lbl_threat_score: "ßï¿ßêÁßîïßëÁ ßïìßîñßëÁ",

        heuristic_metric: "ßï¿ßëÁßèòßë░ßèô ßïÁßîïßìì ßê░ßî¬ ßêÿßê¿ßîâ",

        lbl_crypto_hashes: "ßï¿ßè¡ßê¬ßìòßëÂßîìßê½ßìèßè¡ ßêâßê¥ßë¢",

        lbl_ethio_context: "ßï¿ßèóßëÁßï«ßîÁßï½ ßë░ßëïßêøßëÁ ßï░ßêàßèòßèÉßëÁ ßîìßêØßîêßêø",

        lbl_environment: "ßïÆßêïßêø ßë░ßëïßêØßìí",

        lbl_relevance: "ßï¿ßï░ßêàßèòßèÉßëÁ ßëàßïÁßêÜßï½ßìí",

        lbl_context_reason: "ßï¿ßîìßêØßîêßêø ßêØßè¡ßèòßï½ßëÁßìí",

        pe_analysis_title: "ßï¿ Portable Executable (PE) ßêÿßïïßëàßê¡",

        pe_analysis_subtitle: "ßï¿ DOS headersßìú Optional headersßìú ßï¿ßêÿßîìßëóßï½ ßèáßïÁßê½ßê╗ ßèÑßèô ßï¿ Sections ßèáßï░ßê¿ßîâßîÇßëÁßìó",

        lbl_pe_headers: "ßï¿ PE Headers ßêÿßê¿ßîâßïÄßë¢",

        lbl_entropy_summary: "ßï¿ Entropy ßèÑßèô Anomaly ßêøßîáßëâßêêßï½",

        lbl_sections_table: "ßï¿ PE Memory Sections ßê░ßèòßîáßê¿ßïÑ",

        msg_no_sections: "ßêØßèòßêØ ßï¿ Section ßêÿßê¿ßîâ ßï¿ßêêßêØßìó",

        imports_title: "ßï¿ßë░ßîáßê® Windows APIs ßèÑßèô DLLs",

        imports_subtitle: "ßï¿ßë░ßêÿßï░ßëí ßï¿ßïìßî¡ ßìêßèòßè¡ßê¢ßèûßë¢ ßèÑßèô ßï¿ßìïßï¡ßêë ßë┤ßè¡ßèÆßè½ßïè ßë¢ßêÄßë│ßïÄßë¢ßìó",

        msg_no_imports: "ßêØßèòßêØ ßï¿ßë░ßîáßê½ API ßèáßêìßë░ßîêßèÿßêØßìó",

        strings_title: "ßëáßìïßï¡ßêë ßïìßêÁßîÑ ßï¿ßë░ßîêßèÖ ßî¢ßêüßìÄßë¢",

        strings_subtitle: "ßï¿ßë░ßêÿßï░ßëí ASCII ßèÑßèô Unicode ßî¢ßêüßìÄßë¢ (URLs, IPs, Registry, Commands)ßìó",

        indicators_title: "ßï¿ßë░ßïøßêÿßï▒ ßï¿ßêÁßîïßëÁ ßèáßêÿßêìßè½ßë¥ßë¢",

        indicators_subtitle: "ßëá headersßìú sections ßèÑßèô APIs ßêÿßè½ßè¿ßêì ßï¿ßë░ßïøßêÿßï▒ ßï¿ßï░ßêàßèòßèÉßëÁ ßèáßêÿßêìßè½ßë¥ßë¢ßìó",

        msg_no_indicators: "ßêêßë░ßêÿßê¿ßêÿßê¿ßïì ßìïßï¡ßêì ßêØßèòßêØ ßèáßîáßê½ßîúßê¬ ßèáßêÿßêìßè½ßë¢ ßèáßêìßë░ßîêßèÿßêØßìó",

        ai_analyst_title: "ßï¿ AI ßï¿ßï░ßêàßèòßèÉßëÁ ßë░ßèòßë│ßèØ ßîìßêØßîêßêø",

        ai_analyst_subtitle: "ßï¿ßë░ßîêßèÖ static ßêÿßê¿ßîâßïÄßë¢ßèò ßëáßê│ßï¡ßèòßê│ßïè ßêÿßèòßîêßïÁ ßï¿ßêÜßï½ßëÑßê½ßê½ ßï¿ AI ßëÁßèòßë░ßèôßìó",

        ai_summary_head: "ßï¿ßï░ßêàßèòßèÉßëÁ ßêøßîáßëâßêêßï½",

        ai_key_findings: "ßëüßêìßìì ßîìßèØßëÂßë¢",

        ai_benign_explanations: "ßêèßêåßèæ ßï¿ßêÜßë¢ßêë ßêÿßï░ßëáßèø ßêØßè¡ßèòßï½ßëÂßë¢",

        ai_recommended_investigation: "ßï¿ßêÜßêÿßè¿ßê® ßï¿ßè¡ßëÁßëÁßêì ßèÑßê¡ßêØßîâßïÄßë¢",

        learning_title: "ßï¿ßê│ßï¡ßëáßê¡ ßï░ßêàßèòßèÉßëÁ Reverse-Engineering ßêøßê░ßêìßîáßèø",

        learning_subtitle: "ßêêßë░ßêøßê¬ßïÄßë¢ ßèÑßèô ßêêßï░ßêàßèòßèÉßëÁ ßë░ßêÿßê½ßêøßê¬ßïÄßë¢ ßï¿ßë░ßïÿßîïßîü ßëáßï¡ßèÉ-ßë░ßîìßëúßê½ßïè ßëÁßêØßêàßê¡ßëÂßë¢ßìó",

        select_concept: "ßê¡ßïòßêÁ ßï¡ßêØßê¿ßîí",

        learn_what_is_it: "1. ßï¡ßêà ßêØßèò ßêøßêêßëÁ ßèÉßïì?",

        learn_why_it_matters: "2. ßêêßêØßèò ßï¡ßîáßëàßêøßêì?",

        learn_explanation: "3. ßêøßëÑßê½ßê¬ßï½",

        learn_does_it_prove_malware: "4. ßï¡ßêà ßëÑßë╗ßïìßèò ßë½ßï¡ßê¿ßêÁ ßêÿßêåßèæßèò ßï½ßê¿ßîïßîìßîúßêì?",

        learn_what_next: "5. ßëÇßîÑßêÄ ßêØßèò ßêøßîÑßèôßëÁ ßèáßêêßëÑßèØ?",

    }

};



// Educational Concepts Database (Dual Language & Difficulty)

const CONCEPTS_DB = {

    WINDOWS_APIS: {

        en: {

            title: "Windows APIs & VirtualProtect",

            what_is_it: "Documented OS system calls provided by Microsoft Windows for memory, process, and file operations.",

            why_it_matters: "Categorizing APIs reveals technical primitives without running the file.",

            beginner: "Windows APIs are standard tools provided by Microsoft so programs can safely use memory, draw windows, or read files.",

            advanced: "VirtualProtect alters page permissions via the Virtual Memory Manager (e.g. PAGE_EXECUTE_READWRITE). While essential for JIT compilers, W+X pages violate DEP policies.",

            proves: "No. This API alone does not prove malicious behavior. Legitimate utilities invoke the same APIs for normal tasks.",

            next: ["Study correlated API combinations (e.g. VirtualAlloc + VirtualProtect).", "Learn about user-mode API hooking and native Nt syscalls."]

        },

        am: {

            title: "Windows APIs ßèÑßèô VirtualProtect",

            what_is_it: "ßëá Microsoft Windows ßï¿ßêÜßê░ßîí ßï¿ßêÁßê¡ßïôßëÁ ßîÑßê¬ßïÄßë¢ (System Calls) ßê▓ßêåßèæ ßï¿ßêøßêàßï░ßê¿-ßëÁßïìßêÁßë│ ßèÑßèô ßï¿ßìïßï¡ßêì ßêÁßê½ßïÄßë¢ßèò ßï½ßè¿ßèôßïìßèôßêëßìó",

            why_it_matters: "ßï¿ API ßìêßèòßè¡ßê¢ßèûßë¢ßèò ßêÿßêÿßï░ßëÑ ßï¿ßìïßï¡ßêëßèò ßë┤ßè¡ßèÆßè½ßïè ßë¢ßêÄßë│ ßëáßëÇßêïßêë ßêêßêÿßê¿ßï│ßëÁ ßï½ßêÁßë¢ßêïßêìßìó",

            beginner: "Windows APIs ßìòßê«ßîìßê½ßê×ßë¢ ßè¿ßè«ßêØßìÆßïìßë░ßê® ßîïßê¡ ßëáßê░ßêïßêØ ßèÑßèòßï▓ßèÉßîïßîêßê® ßï¿ßë░ßê░ßê® ßïØßîìßîü ßêÿßêÿßê¬ßï½ßïÄßë¢ ßèôßë©ßïìßìó",

            advanced: "ßèÑßèòßï░ VirtualProtect ßï½ßêë APIs ßï¿ßêøßêàßï░ßê¿-ßëÁßïìßêÁßë│ ßîêßî¢ ßìêßëâßïÁßèò ßïêßï░ PAGE_EXECUTE_READWRITE ßï¡ßëÇßï¡ßê½ßêëßìó ßï¡ßêàßêØ ßêê JIT compilers ßîáßëâßêÜ ßê▓ßêåßèò ßêê W+X ßîÑßèôßëÁßêØ ßï¡ßêÿßê¿ßêÿßê½ßêìßìó",

            proves: "ßèáßï½ßê¿ßîïßîìßîÑßêØßìó ßï¡ßêà API ßëÑßë╗ßïìßèò ßï¿ßêÁßîïßëÁ ßïêßï¡ßêØ ßï¿ßîÑßëâßëÁ ßêøßê¿ßîïßîêßî½ ßêèßêåßèò ßèáßï¡ßë¢ßêìßêØßìó",

            next: ["ßë░ßïøßêøßîà ßï¿ API ßîÑßèòßïÂßë¢ßèò ßêøßîÑßèôßëÁßìó", "ßï¿ Windows Native System Calls ßèáßê░ßê½ßê¡ßèò ßêÿßê¿ßï│ßëÁßìó"]

        }

    },

    PE_FORMAT: {

        en: {

            title: "Portable Executable (PE) Format",

            what_is_it: "The standard file structure used by Windows for executables (.exe) and libraries (.dll).",

            why_it_matters: "Defines how the operating system loader maps binary code into process memory.",

            beginner: "Think of the PE format like the table of contents of a book, telling Windows where code and images are stored.",

            advanced: "PE format contains IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, Section Headers, and Data Directories (IAT, Exports, Resources).",

            proves: "No. The PE format alone does not prove malicious behavior. It is used by virtually all standard Windows software.",

            next: ["Explore Relative Virtual Address (RVA) calculations.", "Learn how the Windows loader parses section headers."]

        },

        am: {

            title: "ßï¿ Portable Executable (PE) ßìÄßê¡ßêøßëÁ",

            what_is_it: "ßëá Windows ßèªßìòßê¼ßë▓ßèòßîì ßê▓ßêÁßë░ßêØ ßêê Executables (.exe) ßèÑßèô DLLs ßï¿ßêÜßï½ßîêßêêßîìßêì ßêÿßï░ßëáßèø ßï¿ßìïßï¡ßêì ßêÿßïïßëàßê¡ ßèÉßïìßìó",

            why_it_matters: "Windows ßìïßï¡ßêÄßë¢ßèò ßïêßï░ ßêøßêàßï░ßê¿-ßëÁßïìßêÁßë│ ßèÑßèòßï┤ßëÁ ßèÑßèòßï░ßêÜßî¡ßèò ßï¡ßîêßêìßî╗ßêìßìó",

            beginner: "PE format ßêìßè¡ ßèÑßèòßï░ ßêÿßî¢ßêÉßìì ßêøßïìßî½ ßèÉßïìßìó ßêê Windows ßï¿ßëÁßèøßïì ßè¡ßììßêì ßè«ßïÁ ßèÑßèòßï░ßêåßèÉ ßï¡ßèÉßîìßê¿ßïïßêìßìó",

            advanced: "ßï¿ PE ßêÿßïïßëàßê¡ ßè¿ DOS MZ header ßë░ßèÉßêÁßëÂ ßïêßï░ IMAGE_NT_HEADERS ßï¡ßê©ßîïßîêßê½ßêìßìñ ßï¡ßêàßêØ ImageBase ßèÑßèô DataDirectory ßèò ßï½ßè½ßëÁßë│ßêìßìó",

            proves: "ßèáßï½ßê¿ßîïßîìßîÑßêØßìó ßï¡ßêà ßêÿßïïßëàßê¡ ßëÑßë╗ßïìßèò ßï¿ßêÁßîïßëÁ ßïêßï¡ßêØ ßï¿ßîÑßëâßëÁ ßêøßê¿ßîïßîêßî½ ßêèßêåßèò ßèáßï¡ßë¢ßêìßêØßìó",

            next: ["ßï¿ Relative Virtual Address (RVA) ßêÁßêîßëÁßèò ßêÿßêøßê¡ßìó", "ßï¿ PE loader ßèáßê░ßê½ßê¡ßèò ßêÿßêÿßê¡ßêÿßê¡ßìó"]

        }

    },

    ENTROPY: {

        en: {

            title: "Shannon Entropy & Randomness",

            what_is_it: "A mathematical measurement of information density on a scale from 0.0 to 8.0.",

            why_it_matters: "High entropy (> 7.2) indicates compressed data, encrypted payloads, or software packing.",

            beginner: "Entropy measures how crowded and jumbled data is. Plain text has low entropy; encrypted or zipped files have very high entropy.",

            advanced: "Shannon entropy H(X) = -sum(p * log2(p)). In PE analysis, section entropy is correlated with raw-to-virtual size ratios to detect runtime unpackers.",

            proves: "No. High entropy alone does not prove malicious behavior. It is completely normal for compressed media (PNG/ZIP) and installers.",

            next: ["Calculate entropy per section to isolate packed stubs.", "Learn how to distinguish standard compression from custom encryption."]

        },

        am: {

            title: "ßï¿ Shannon Entropy ßèÑßèô ßï¿ßêÿßê¿ßîâ ßèÑßììßîïßëÁ",

            what_is_it: "ßï¿ßêÿßê¿ßîâßèò ßïÁßëÑßêìßëàßèÉßëÁ ßèÑßèô ßèÑßììßîïßëÁ ßè¿ 0.0 ßèÑßêÁßè¿ 8.0 ßëáßêÜßï░ßê¡ßêÁ ßï¿ßêéßê│ßëÑ ßëÇßêÿßê¡ ßï¿ßêÜßêêßè½ ßêÁßêîßëÁ ßèÉßïìßìó",

            why_it_matters: "ßè¿ßììßë░ßèø Entropy (> 7.2) ßï¿ßë│ßêÿßëÇ ßïêßï¡ßêØ ßï¿ßë░ßêÿßê░ßîáßê¿ ßï│ßë│ ßêÿßèûßê®ßèò ßï½ßêÿßêêßè¡ßë│ßêìßìó",

            beginner: "Entropy ßï│ßë│ßïì ßêØßèò ßï½ßêàßêì ßï¿ßë░ßïÿßëáßê½ßê¿ßëÇ ßèÑßèòßï░ßêåßèÉ ßï¡ßêêßè½ßêìßìñ ßï¿ßë░ßêÿßê░ßîáßê® ßïêßï¡ßêØ ßïÜßìò ßï¿ßë░ßï░ßê¿ßîë ßìïßï¡ßêÄßë¢ ßè¿ßììßë░ßèø Entropy ßèáßêïßë©ßïìßìó",

            advanced: "ßï¿ Shannon entropy ßëáßèáßèòßïÁ ßëúßï¡ßëÁ ßïìßêÁßîÑ ßï½ßêêßïìßèò ßï¿ßêÿßê¿ßîâ ßèÑßê¡ßîìßîáßèø-ßèáßêìßëúßèÉßëÁ ßï¡ßêêßè½ßêìßìó ßëá PE ßëÁßèòßë░ßèô packing ßèò ßêêßêÿßêêßï¿ßëÁ ßï¡ßê¿ßï│ßêìßìó",

            proves: "ßèáßï½ßê¿ßîïßîìßîÑßêØßìó ßè¿ßììßë░ßèø Entropy ßëÑßë╗ßïìßèò ßï¿ßêÁßîïßëÁ ßïêßï¡ßêØ ßï¿ßîÑßëâßëÁ ßêøßê¿ßîïßîêßî½ ßêèßêåßèò ßèáßï¡ßë¢ßêìßêØßìó",

            next: ["ßï¿ßèÑßï½ßèòßï│ßèòßï▒ßèò section entropy ßêêßï¡ßëÂ ßêøßêÁßêïßëÁßìó", "ßëá compression ßèÑßèô encryption ßêÿßè½ßè¿ßêì ßï½ßêêßïìßèò ßêìßï®ßèÉßëÁ ßêÿßê¿ßï│ßëÁßìó"]

        }

    }

};



// =========================================================

// 1. CYBER DEFENSE BACKGROUND GRID CANVAS

// =========================================================

let cyberGridAnimFrame = null;

function initCyberGrid() {

    const canvas = document.getElementById('cyber-bg-canvas');

    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    if (!ctx) return;



    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReducedMotion) {

        canvas.width = window.innerWidth;

        canvas.height = window.innerHeight;

        drawStaticGrid(ctx, canvas.width, canvas.height);

        return;

    }



    let width = (canvas.width = window.innerWidth);

    let height = (canvas.height = window.innerHeight);



    window.addEventListener('resize', () => {

        width = canvas.width = window.innerWidth;

        height = canvas.height = window.innerHeight;

    });



    const particles = [];

    const numParticles = Math.min(30, Math.floor((width * height) / 50000));



    for (let i = 0; i < numParticles; i++) {

        particles.push({

            x: Math.random() * width,

            y: Math.random() * height,

            vx: (Math.random() - 0.5) * 0.3,

            vy: (Math.random() - 0.5) * 0.3,

            radius: Math.random() * 1.5 + 0.8,

            alpha: Math.random() * 0.25 + 0.1,

        });

    }



    function animate() {

        ctx.clearRect(0, 0, width, height);



        // Draw tactical background grid lines

        const gridSize = 64;

        ctx.strokeStyle = 'rgba(56, 189, 248, 0.022)';

        ctx.lineWidth = 1;



        ctx.beginPath();

        for (let x = 0; x < width; x += gridSize) {

            ctx.moveTo(x, 0);

            ctx.lineTo(x, height);

        }

        for (let y = 0; y < height; y += gridSize) {

            ctx.moveTo(0, y);

            ctx.lineTo(width, y);

        }

        ctx.stroke();



        // Update and draw telemetry nodes

        for (let i = 0; i < particles.length; i++) {

            const p = particles[i];

            p.x += p.vx;

            p.y += p.vy;



            if (p.x < 0) p.x = width;

            if (p.x > width) p.x = 0;

            if (p.y < 0) p.y = height;

            if (p.y > height) p.y = 0;



            ctx.fillStyle = `rgba(0, 240, 255, ${p.alpha})`;

            ctx.beginPath();

            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);

            ctx.fill();



            // Connect nearby nodes

            for (let j = i + 1; j < particles.length; j++) {

                const p2 = particles[j];

                const dx = p.x - p2.x;

                const dy = p.y - p2.y;

                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 100) {

                    const lineAlpha = (1 - dist / 100) * 0.07;

                    ctx.strokeStyle = `rgba(0, 240, 255, ${lineAlpha})`;

                    ctx.beginPath();

                    ctx.moveTo(p.x, p.y);

                    ctx.lineTo(p2.x, p2.y);

                    ctx.stroke();

                }

            }

        }



        cyberGridAnimFrame = requestAnimationFrame(animate);

    }



    animate();

}



function drawStaticGrid(ctx, width, height) {

    const gridSize = 64;

    ctx.strokeStyle = 'rgba(56, 189, 248, 0.022)';

    ctx.lineWidth = 1;

    ctx.beginPath();

    for (let x = 0; x < width; x += gridSize) {

        ctx.moveTo(x, 0);

        ctx.lineTo(x, height);

    }

    for (let y = 0; y < height; y += gridSize) {

        ctx.moveTo(0, y);

        ctx.lineTo(width, y);

    }

    ctx.stroke();

}



// =========================================================

// 2. DYNAMIC NUMBER COUNTER ENGINE

// =========================================================

function animateCounter(elementOrId, targetValue, duration = 800) {

    const el = typeof elementOrId === 'string' ? document.getElementById(elementOrId) : elementOrId;

    if (!el) return;



    const target = Number(targetValue) || 0;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReducedMotion) {

        el.textContent = target.toLocaleString();

        return;

    }



    const current = Number(el.textContent.replace(/[^0-9.-]+/g, '')) || 0;

    if (current === target) {

        el.textContent = target.toLocaleString();

        return;

    }



    const startTime = performance.now();

    function step(now) {

        const elapsed = now - startTime;

        const progress = Math.min(elapsed / duration, 1);

        const ease = 1 - (1 - progress) * (1 - progress);

        const val = Math.round(current + (target - current) * ease);

        el.textContent = val.toLocaleString();

        if (progress < 1) {

            requestAnimationFrame(step);

        } else {

            el.textContent = target.toLocaleString();

        }

    }

    requestAnimationFrame(step);

}



// =========================================================

// 3. CIRCULAR THREAT RISK GAUGE ANIMATOR

// =========================================================

function renderThreatGauge(score, riskLevel) {

    const gaugeCircle = document.getElementById('ov-threat-gauge-circle');

    const tierBadgeEl = document.getElementById('ov-tier-badge');

    const riskBadgeEl = document.getElementById('ov-risk-level');

    const riskTextEl = document.getElementById('ov-risk-level-text');



    const numScore = Math.min(100, Math.max(0, Number(score) || 0));

    const level = (riskLevel || (numScore >= 85 ? 'CRITICAL' : (numScore >= 70 ? 'HIGH' : (numScore >= 40 ? 'SUSPICIOUS' : 'LOW')))).toUpperCase();



    // Circumference = 2 * PI * 68 = ~427.25

    const circumference = 427.25;

    const offset = circumference - (numScore / 100) * circumference;



    if (gaugeCircle) {

        gaugeCircle.style.strokeDasharray = `${circumference}`;

        gaugeCircle.style.strokeDashoffset = `${offset}`;

        

        gaugeCircle.classList.remove('gauge-low', 'gauge-susp', 'gauge-high', 'gauge-crit');

        if (numScore >= 85 || level === 'CRITICAL') {

            gaugeCircle.classList.add('gauge-crit');

        } else if (numScore >= 70 || level === 'HIGH') {

            gaugeCircle.classList.add('gauge-high');

        } else if (numScore >= 40 || level === 'SUSPICIOUS' || level === 'MEDIUM') {

            gaugeCircle.classList.add('gauge-susp');

        } else {

            gaugeCircle.classList.add('gauge-low');

        }

    }



    animateCounter('ov-score-num', numScore, 900);



    if (tierBadgeEl) {

        tierBadgeEl.textContent = level;

        tierBadgeEl.className = 'gauge-tier-badge ' + (numScore >= 85 ? 'crit' : (numScore >= 70 ? 'high' : (numScore >= 40 ? 'susp' : 'low')));

    }



    if (riskTextEl) {

        riskTextEl.textContent = level;

    }

    if (riskBadgeEl) {

        riskBadgeEl.className = 'badge ' + getRiskBadgeClass(level);

    }

}



// =========================================================

// 4. DEFENSIVE ANALYSIS PIPELINE VISUALIZATION

// =========================================================

function updateAnalysisPipeline(activeStageIndex = 10, containerId = 'overview-pipeline-stages') {

    const container = document.getElementById(containerId);

    if (!container) return;



    const stages = container.querySelectorAll('.pipeline-stage');

    stages.forEach((stage, idx) => {

        const stageNum = idx + 1;

        stage.classList.remove('active', 'completed', 'waiting');

        if (stageNum < activeStageIndex) {

            stage.classList.add('completed');

            const node = stage.querySelector('.stage-node');

            if (node) node.textContent = 'Ô£ô';

        } else if (stageNum === activeStageIndex) {

            stage.classList.add('active');

            const node = stage.querySelector('.stage-node');

            if (node) node.textContent = stageNum;

        } else {

            stage.classList.add('waiting');

            const node = stage.querySelector('.stage-node');

            if (node) node.textContent = stageNum;

        }

    });

}



// =========================================================

// 5. FORENSIC THREAT RELATIONSHIP EVIDENCE GRAPH

// =========================================================

function renderThreatRelationshipMap(data) {

    if (!data) return;



    const fi = data.file_information || data.file || {};

    const imp = data.imports || { imports: [] };

    const importsList = Array.isArray(imp) ? imp : (imp.imports || []);

    const suspiciousApis = importsList.filter(i => (i.risk_relevance || '').toUpperCase() === 'HIGH' || (i.risk_relevance || '').toUpperCase() === 'CRITICAL');



    const indData = data.indicators || { indicators: [] };

    const indicatorsList = Array.isArray(indData) ? indData : (indData.indicators || []);



    const mitreData = data.mitre_attack || data.mitre || [];

    const mitreList = Array.isArray(mitreData) ? mitreData : (mitreData.techniques || []);



    const filenameEl = document.getElementById('graph-filename');

    const filesizeEl = document.getElementById('graph-filesize');

    const apiCountEl = document.getElementById('graph-api-count');

    const iocCountEl = document.getElementById('graph-ioc-count');

    const mitreEl = document.getElementById('graph-mitre-technique');



    if (filenameEl) filenameEl.textContent = fi.filename || data.filename || 'sample.exe';

    if (filesizeEl) filesizeEl.textContent = `${((fi.file_size || data.size || 0) / 1024).toFixed(1)} KB`;

    if (apiCountEl) apiCountEl.textContent = `${suspiciousApis.length} Suspicious APIs`;

    if (iocCountEl) iocCountEl.textContent = `${indicatorsList.length} Heuristic IOCs`;

    if (mitreEl) {

        if (mitreList.length > 0) {

            mitreEl.textContent = mitreList.map(m => m.id || m.technique_id).slice(0, 2).join(' / ');

        } else {

            mitreEl.textContent = 'None Mapped';

        }

    }

}



// =========================================================

// 6. RIGHT-SIDE FORENSIC INVESTIGATION DRAWER

// =========================================================

let currentDrawerContent = '';

function openInvestigationDrawer(title, metadata = {}) {

    const drawer = document.getElementById('investigation-drawer');

    const overlay = document.getElementById('investigation-drawer-overlay');

    const titleEl = document.getElementById('drawer-title');

    const bodyEl = document.getElementById('drawer-body');



    if (!drawer || !bodyEl) return;



    if (titleEl) titleEl.textContent = title || 'Forensic Artifact Investigation';



    let html = `

        <div style="display: flex; flex-direction: column; gap: 14px;">

            <div style="background: rgba(0, 240, 255, 0.05); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: 6px; padding: 12px;">

                <div style="font-size: 11px; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; margin-bottom: 4px;">Primary Artifact:</div>

                <pre style="margin: 0; font-family: var(--font-mono); font-size: 12px; color: var(--text-primary); word-break: break-all; white-space: pre-wrap;">${escapeHtml(metadata.value || metadata.name || title)}</pre>

            </div>

    `;



    currentDrawerContent = metadata.value || metadata.name || title;



    if (metadata.category || metadata.severity || metadata.offset || metadata.encoding) {

        html += `

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">

                ${metadata.category ? `<div style="background: var(--bg-card-alt); padding: 8px; border-radius: 4px; border: 1px solid var(--border-subtle);"><span style="font-size: 10px; color: var(--text-muted); text-transform: uppercase; display: block;">Category</span><strong style="font-size: 12px; color: var(--text-primary);">${escapeHtml(metadata.category)}</strong></div>` : ''}

                ${metadata.severity ? `<div style="background: var(--bg-card-alt); padding: 8px; border-radius: 4px; border: 1px solid var(--border-subtle);"><span style="font-size: 10px; color: var(--text-muted); text-transform: uppercase; display: block;">Severity</span><span class="badge ${getRiskBadgeClass(metadata.severity)}">${escapeHtml(metadata.severity)}</span></div>` : ''}

                ${metadata.offset ? `<div style="background: var(--bg-card-alt); padding: 8px; border-radius: 4px; border: 1px solid var(--border-subtle);"><span style="font-size: 10px; color: var(--text-muted); text-transform: uppercase; display: block;">Byte Offset</span><strong style="font-size: 12px; font-family: var(--font-mono); color: var(--accent-cyan);">${escapeHtml(metadata.offset)}</strong></div>` : ''}

                ${metadata.encoding ? `<div style="background: var(--bg-card-alt); padding: 8px; border-radius: 4px; border: 1px solid var(--border-subtle);"><span style="font-size: 10px; color: var(--text-muted); text-transform: uppercase; display: block;">Encoding</span><strong style="font-size: 12px; color: var(--text-primary);">${escapeHtml(metadata.encoding)}</strong></div>` : ''}

            </div>

        `;

    }



    if (metadata.description || metadata.evidence || metadata.reason) {

        html += `

            <div style="background: var(--bg-card-alt); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 12px;">

                <div style="font-size: 11px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 4px;">Forensic Assessment:</div>

                <div style="font-size: 12px; color: var(--text-primary); line-height: 1.5;">${escapeHtml(metadata.description || metadata.evidence || metadata.reason)}</div>

            </div>

        `;

    }



    if (metadata.mitre_technique || metadata.mitre_id) {

        html += `

            <div style="background: rgba(14, 165, 233, 0.08); border: 1px solid rgba(14, 165, 233, 0.3); border-radius: 6px; padding: 12px;">

                <div style="font-size: 11px; font-weight: 700; color: var(--accent-blue); text-transform: uppercase; margin-bottom: 4px;">MITRE ATT&CK Mapping:</div>

                <div style="font-size: 12px; font-weight: 700; color: var(--text-primary);">${escapeHtml(metadata.mitre_id || '')} ÔÇö ${escapeHtml(metadata.mitre_technique || '')}</div>

                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Static presence alone does not establish confirmed runtime execution.</div>

            </div>

        `;

    }



    html += `</div>`;

    bodyEl.innerHTML = html;



    drawer.classList.add('open');

    if (overlay) overlay.classList.add('open');

}



function closeInvestigationDrawer() {

    const drawer = document.getElementById('investigation-drawer');

    const overlay = document.getElementById('investigation-drawer-overlay');

    if (drawer) drawer.classList.remove('open');

    if (overlay) overlay.classList.remove('open');

}



function copyDrawerContent() {

    if (!currentDrawerContent) return;

    navigator.clipboard.writeText(currentDrawerContent).then(() => {

        const btn = document.getElementById('btn-drawer-copy');

        if (btn) {

            const orig = btn.textContent;

            btn.textContent = 'Ô£ô Copied!';

            setTimeout(() => { btn.textContent = orig; }, 1800);

        }

    });

}



// =========================================================

// 7. FLOATING SOC TOAST NOTIFICATION CENTER

// =========================================================

function showSocNotification(title, message, type = 'info', actionText = null, actionCallback = null) {

    const container = document.getElementById('soc-toast-container');

    if (!container) return;



    const toast = document.createElement('div');

    toast.className = `soc-toast ${type}`;



    const iconMap = {

        success: 'Ô£ô',

        warning: 'ÔÜá´©Å',

        critical: '­ƒøæ',

        info: 'Ôä╣´©Å'

    };



    toast.innerHTML = `

        <div class="toast-icon">${iconMap[type] || '­ƒøí´©Å'}</div>

        <div class="toast-content">

            <div class="toast-title">${escapeHtml(title)}</div>

            <div class="toast-message">${escapeHtml(message)}</div>

            ${actionText ? `<div style="margin-top: 6px;"><button class="btn-primary" id="toast-action-btn" style="font-size: 10px; padding: 2px 8px;">${escapeHtml(actionText)}</button></div>` : ''}

        </div>

        <button class="toast-close" aria-label="Close Notification">Ô£ò</button>

    `;



    const closeBtn = toast.querySelector('.toast-close');

    if (closeBtn) {

        closeBtn.addEventListener('click', () => {

            toast.style.opacity = '0';

            toast.style.transform = 'translateX(20px)';

            setTimeout(() => toast.remove(), 250);

        });

    }



    if (actionText && actionCallback) {

        const actBtn = toast.querySelector('#toast-action-btn');

        if (actBtn) {

            actBtn.addEventListener('click', () => {

                actionCallback();

                toast.remove();

            });

        }

    }



    container.appendChild(toast);



    setTimeout(() => {

        if (toast.parentElement) {

            toast.style.opacity = '0';

            toast.style.transform = 'translateX(20px)';

            setTimeout(() => toast.remove(), 300);

        }

    }, 5500);

}



// =========================================================

// 8. LIVE PLATFORM DEFENSIVE SUBSYSTEM HEALTH

// =========================================================

async function loadSystemHealth() {

    const listEl = document.getElementById('system-health-list');

    const dbStatusEl = document.getElementById('admin-health-db-status');



    try {

        const res = await fetchWithAuth('/api/auth/system/health');

        if (!res || !res.ok) return;

        const data = await res.json();



        if (listEl && data.subsystems) {

            listEl.innerHTML = data.subsystems.map(sub => `

                <div class="flex-between" style="padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-subtle); border-radius: 6px;">

                    <div>

                        <strong style="font-size: 13px; color: var(--text-primary);">${escapeHtml(sub.name)}</strong>

                        <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(sub.description)}</div>

                    </div>

                    <div style="text-align: right;">

                        <span class="badge ${sub.status === 'ONLINE' ? 'badge-low' : 'badge-crit'}">ÔùÅ ${escapeHtml(sub.status)}</span>

                        <div style="font-size: 10px; color: var(--text-dim); font-family: var(--font-mono); margin-top: 2px;">${escapeHtml(sub.latency_ms || '<1ms')}</div>

                    </div>

                </div>

            `).join('');

        }



        if (dbStatusEl) {

            dbStatusEl.textContent = 'ÔùÅ ONLINE';

            dbStatusEl.style.color = 'var(--sev-low)';

        }

    } catch (err) {

        if (listEl) listEl.innerHTML = `<div class="empty-state-cell">Error loading system health: ${escapeHtml(err.message)}</div>`;

    }

}



function openSystemHealthModal() {

    const modal = document.getElementById('system-health-modal');

    if (modal) {

        modal.style.display = 'flex';

        loadSystemHealth();

    }

}



function closeSystemHealthModal() {

    const modal = document.getElementById('system-health-modal');

    if (modal) modal.style.display = 'none';

}



// =========================================================

// 9. LIVE DEFENSIVE DASHBOARD TELEMETRY & HUD OVERVIEW

// =========================================================

async function loadDashboardOverviewStats() {

    try {

        const res = await fetchWithAuth('/api/analyses/overview-stats');

        if (!res || !res.ok) return;

        const data = await res.json();



        // 1. Animate Hero Counters

        animateCounter('dash-total-analyses', data.total_analyses || 0);

        animateCounter('dash-high-critical', (data.high_risk_count || 0) + (data.critical_risk_count || 0));



        animateCounter('dash-count-low', data.low_risk_count || 0);

        animateCounter('dash-count-med', data.medium_risk_count || 0);

        animateCounter('dash-count-high', data.high_risk_count || 0);

        animateCounter('dash-count-crit', data.critical_risk_count || 0);



        // 2. Risk Distribution Donut Chart

        const total = Math.max(1, data.total_analyses || 0);

        const lowPct = Math.round(((data.low_risk_count || 0) / total) * 100);

        const medPct = Math.round(((data.medium_risk_count || 0) / total) * 100);

        const highPct = Math.round(((data.high_risk_count || 0) / total) * 100);

        const critPct = Math.round(((data.critical_risk_count || 0) / total) * 100);



        const legendLow = document.getElementById('dash-legend-low');

        const legendMed = document.getElementById('dash-legend-med');

        const legendHigh = document.getElementById('dash-legend-high');

        const legendCrit = document.getElementById('dash-legend-crit');

        if (legendLow) legendLow.textContent = `${lowPct}%`;

        if (legendMed) legendMed.textContent = `${medPct}%`;

        if (legendHigh) legendHigh.textContent = `${highPct}%`;

        if (legendCrit) legendCrit.textContent = `${critPct}%`;



        // SVG Donut circumference = 2 * PI * 40 Ôëê 251.327

        const C = 251.327;

        const segLow = document.getElementById('donut-segment-low');

        const segMed = document.getElementById('donut-segment-med');

        const segHigh = document.getElementById('donut-segment-high');

        const segCrit = document.getElementById('donut-segment-crit');



        const lowLen = (lowPct / 100) * C;

        const medLen = (medPct / 100) * C;

        const highLen = (highPct / 100) * C;

        const critLen = (critPct / 100) * C;



        if (segLow) {

            segLow.style.strokeDasharray = `${lowLen} ${C}`;

            segLow.style.strokeDashoffset = '0';

        }

        if (segMed) {

            segMed.style.strokeDasharray = `${medLen} ${C}`;

            segMed.style.strokeDashoffset = `-${lowLen}`;

        }

        if (segHigh) {

            segHigh.style.strokeDasharray = `${highLen} ${C}`;

            segHigh.style.strokeDashoffset = `-${lowLen + medLen}`;

        }

        if (segCrit) {

            segCrit.style.strokeDasharray = `${critLen} ${C}`;

            segCrit.style.strokeDashoffset = `-${lowLen + medLen + highLen}`;

        }



        // Center Avg Score

        const avgScore = total > 0 ? Math.round(((data.low_risk_count * 15) + (data.medium_risk_count * 55) + (data.high_risk_count * 78) + (data.critical_risk_count * 92)) / total) : 0;

        const avgEl = document.getElementById('dash-donut-avg-score');

        if (avgEl) animateCounter('dash-donut-avg-score', avgScore);



        const avgBadge = document.getElementById('dash-overall-risk-badge');

        if (avgBadge) {

            const lvl = avgScore >= 85 ? 'CRITICAL' : (avgScore >= 70 ? 'HIGH' : (avgScore >= 40 ? 'SUSPICIOUS' : 'LOW'));

            avgBadge.textContent = lvl;

            avgBadge.className = 'badge ' + getRiskBadgeClass(lvl);

        }



        // 3. Top Threat Indicators Meters

        const ind = data.top_threat_indicators || {};

        const maxInd = Math.max(1, (ind.suspicious_apis || 0) + (ind.malicious_strings || 0) + (ind.network_indicators || 0) + (ind.registry_indicators || 0) + (ind.high_entropy || 0));



        const setMeter = (valId, barId, count) => {

            const v = document.getElementById(valId);

            const b = document.getElementById(barId);

            const pct = Math.min(100, Math.round((count / maxInd) * 100));

            if (v) animateCounter(valId, count);

            if (b) b.style.width = `${pct}%`;

        };



        setMeter('meter-apis-val', 'meter-apis-bar', ind.suspicious_apis || 0);

        setMeter('meter-strings-val', 'meter-strings-bar', ind.malicious_strings || 0);

        setMeter('meter-net-val', 'meter-net-bar', ind.network_indicators || 0);

        setMeter('meter-reg-val', 'meter-reg-bar', ind.registry_indicators || 0);

        setMeter('meter-entropy-val', 'meter-entropy-bar', ind.high_entropy || 0);



        // 4. IOC Intelligence Counts

        const ioc = data.ioc_counts || {};

        const totalIocBadge = document.getElementById('dash-ioc-total-badge');

        if (totalIocBadge) totalIocBadge.textContent = `${ioc.total || 0} ARTIFACTS`;



        animateCounter('dash-ioc-domains', ioc.domains || 0);

        animateCounter('dash-ioc-ips', ioc.ips || 0);

        animateCounter('dash-ioc-urls', ioc.urls || 0);

        animateCounter('dash-ioc-hashes', ioc.hashes || 0);

        animateCounter('dash-ioc-registry', ioc.registry || 0);



        // 5. Recent Activity List

        const actList = document.getElementById('dash-recent-activity-list');

        if (actList) {

            if (!data.recent_activity || data.recent_activity.length === 0) {

                actList.innerHTML = '<div class="empty-state-cell">No recent binary analyses recorded.</div>';

            } else {

                actList.innerHTML = data.recent_activity.map(item => `

                    <div class="recent-activity-item" onclick="loadAnalysisById('${escapeJsString(item.analysis_id)}')">

                        <div class="recent-activity-info">

                            <span class="recent-activity-name">${escapeHtml(item.filename)}</span>

                            <span class="recent-activity-meta">ID: ${escapeHtml(item.analysis_id)} ÔÇó SHA: ${escapeHtml(item.sha256_short)}</span>

                        </div>

                        <div style="text-align: right;">

                            <span class="badge ${getRiskBadgeClass(item.classification)}">${escapeHtml(item.classification)} (${item.risk_score})</span>

                            <div style="font-size: 9px; color: var(--text-dim); margin-top: 2px;">${item.created_at ? item.created_at.substring(0, 10) : ''}</div>

                        </div>

                    </div>

                `).join('');

            }

        }

    } catch (err) {

        console.warn('Error loading dashboard overview stats:', err);

    }

}



// Initialization on DOM Loaded

document.addEventListener('DOMContentLoaded', () => {

    initCyberGrid();

    initNavigation();

    initUploadDropzone();

    initLanguage();

    initAuth();

    renderSelectedConcept();

    loadDashboardOverviewStats();

});



/**

 * Tab Navigation Setup

 */

function initNavigation() {

    const navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(btn => {

        btn.addEventListener('click', () => {

            const tabId = btn.getAttribute('data-tab');

            switchTab(tabId);

        });

    });



    // Browser back/forward navigation support

    window.addEventListener('popstate', () => {

        handleUrlRouting();

    });



    // Mobile Menu Toggle

    const mobileToggle = document.getElementById('mobile-menu-toggle');

    const sidebar = document.getElementById('sidebar');

    if (mobileToggle && sidebar) {

        mobileToggle.addEventListener('click', () => {

            sidebar.classList.toggle('open');

        });

    }

}



function switchTab(tabId, updateUrl = true) {

    // If not authenticated, ensure public layout is shown and redirect to /login

    if (state.authStatus !== 'AUTHENTICATED' && tabId !== 'unauthorized') {

        renderLayoutForAuth();

        updateUrlPath('/login');

        switchAuthTab('login');

        return;

    }



    if (tabId === 'admin') {

        if (!state.user || state.user.role !== 'ADMIN') {

            showUnauthorizedView("Access Denied: Only Administrator accounts can access User Management & Security Audit features.");

            return;

        }

        if (updateUrl) updateUrlPath('/admin/dashboard');

    } else if (tabId === 'home' && state.user && state.user.role === 'STUDENT') {

        // SEC-05 / P1: Students have no UPLOAD_FILES permission, so the generic

        // binary upload intake view must not be reachable. Show an explicit

        // access-denied view directing them to the Safe Practice Labs.

        showUnauthorizedView("Access Denied: Uploading binaries is restricted to Analysts and Administrators. Please use the Safe Practice Labs.");

        return;

    } else if (tabId === 'learning') {

        if (updateUrl && state.user && state.user.role === 'STUDENT') {

            updateUrlPath('/student/dashboard');

        }

    } else if (['home', 'history', 'analysis', 'pe-analysis', 'imports', 'strings', 'indicators', 'ai-analyst', 'reports'].includes(tabId)) {

        if (updateUrl && state.user && state.user.role === 'ANALYST') {

            updateUrlPath(tabId === 'home' ? '/analyst/dashboard' : `/${tabId === 'ai-analyst' ? 'ai-analysis' : tabId}`);

        }

    }



    state.currentTab = tabId;



    // Update active nav link

    document.querySelectorAll('.nav-link').forEach(btn => {

        btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);

    });



    // Update active view panel

    document.querySelectorAll('.view-panel').forEach(panel => {

        panel.classList.toggle('active', panel.id === `view-${tabId}`);

    });



    // Update topbar title

    const activeBtn = document.querySelector(`.nav-link[data-tab="${tabId}"] .nav-label`);

    if (activeBtn) {

        document.getElementById('topbar-active-title').textContent = activeBtn.textContent;

    }



    if (tabId === 'home') {

        loadDashboardOverviewStats();

    } else if (tabId === 'admin') {

        switchAdminTab(state.adminCurrentSubtab || 'overview');

    } else if (tabId === 'history') {

        loadAnalysisHistory();

    } else if (tabId === 'learning') {

        switchStudentTab(state.studentCurrentSubtab || 'concepts');

    } else if (tabId === 'strings') {

        loadStringsIntelligence();

    } else if (tabId === 'pe-analysis') {

        loadPeStructureAnalysis();

    } else if (tabId === 'imports') {

        loadImportsIntelligence();

    } else if (tabId === 'indicators') {

        loadIndicatorsAndIocs();

    } else if (tabId === 'ai-analyst') {

        loadAiAnalystView();

    } else if (tabId === 'reports') {

        loadReportsView();

    }



    // Close sidebar on mobile

    const sidebar = document.getElementById('sidebar');

    if (sidebar) sidebar.classList.remove('open');

}



/**

 * Language Switching (EN / AM)

 */

function setLanguage(lang) {

    state.currentLanguage = lang;



    // Toggle button UI in both layouts

    const btnEn = document.getElementById('lang-btn-en');

    const btnAm = document.getElementById('lang-btn-am');

    if (btnEn) btnEn.classList.toggle('active', lang === 'en');

    if (btnAm) btnAm.classList.toggle('active', lang === 'am');



    const pubBtnEn = document.getElementById('public-lang-btn-en');

    const pubBtnAm = document.getElementById('public-lang-btn-am');

    if (pubBtnEn) pubBtnEn.classList.toggle('active', lang === 'en');

    if (pubBtnAm) pubBtnAm.classList.toggle('active', lang === 'am');



    // Translate all elements with data-i18n attribute

    const dictionary = I18N[lang] || I18N.en;

    document.querySelectorAll('[data-i18n]').forEach(el => {

        const key = el.getAttribute('data-i18n');

        if (dictionary[key]) {

            el.textContent = dictionary[key];

        }

    });



    // Re-render concept breakdown in selected language

    renderSelectedConcept();



    // Re-render user auth widget and banner in selected language

    renderUserAuthWidget();



    // Re-render role navigation labels in selected language

    renderNavigationForRole();



    // If a sample is loaded, re-render its text if appropriate

    if (state.sampleData) {

        renderSampleData(state.sampleData);

    }

}



function initLanguage() {

    setLanguage('en');

}



/**

 * File Upload & Staged Intake Handling

 */

function initUploadDropzone() {

    const dropzone = document.getElementById('upload-dropzone');

    const fileInput = document.getElementById('file-upload-input');

    const browseBtn = document.getElementById('btn-browse-file');



    if (!dropzone || !fileInput) return;



    if (browseBtn) {

        browseBtn.addEventListener('click', (e) => {

            e.stopPropagation();

            fileInput.click();

        });

    }



    dropzone.addEventListener('click', () => fileInput.click());



    dropzone.addEventListener('dragover', (e) => {

        e.preventDefault();

        dropzone.classList.add('dragover');

    });



    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));



    dropzone.addEventListener('drop', (e) => {

        e.preventDefault();

        dropzone.classList.remove('dragover');

        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {

            handleFileSelected(e.dataTransfer.files[0]);

        }

    });



    fileInput.addEventListener('change', () => {

        if (fileInput.files && fileInput.files.length > 0) {

            handleFileSelected(fileInput.files[0]);

        }

    });

}



function handleFileSelected(file) {

    const errBox = document.getElementById('upload-error-box');

    if (errBox) errBox.style.display = 'none';



    if (!file) return;



    const ext = (file.name.split('.').pop() || '').toLowerCase();

    if (!['exe', 'dll'].includes(ext)) {

        if (errBox) {

            errBox.textContent = `Unsupported file type .${ext}. Only Windows PE executables (.exe, .dll) are accepted.`;

            errBox.style.display = 'block';

        }

        return;

    }



    if (file.size > 50 * 1024 * 1024) {

        if (errBox) {

            errBox.textContent = `File exceeds maximum allowed size of 50 MB (${(file.size / (1024 * 1024)).toFixed(1)} MB).`;

            errBox.style.display = 'block';

        }

        return;

    }



    state.selectedFile = file;



    // Display Selected File Card

    const dropzone = document.getElementById('upload-dropzone');

    const selCard = document.getElementById('upload-selected-card');

    const progCard = document.getElementById('upload-progress-card');



    if (dropzone) dropzone.style.display = 'none';

    if (progCard) progCard.style.display = 'none';



    if (selCard) {

        document.getElementById('selected-file-name').textContent = file.name;

        document.getElementById('selected-file-size').textContent = `${(file.size / 1024).toFixed(1)} KB`;

        document.getElementById('selected-file-ext').textContent = `.${ext.toUpperCase()}`;

        selCard.style.display = 'block';

    }

}



function clearSelectedFile() {

    state.selectedFile = null;

    const fileInput = document.getElementById('file-upload-input');

    if (fileInput) fileInput.value = '';



    const dropzone = document.getElementById('upload-dropzone');

    const selCard = document.getElementById('upload-selected-card');

    const progCard = document.getElementById('upload-progress-card');

    const errBox = document.getElementById('upload-error-box');



    if (dropzone) dropzone.style.display = 'flex';

    if (selCard) selCard.style.display = 'none';

    if (progCard) progCard.style.display = 'none';

    if (errBox) errBox.style.display = 'none';

}



async function startSelectedFileAnalysis() {

    if (!state.selectedFile) return;



    const file = state.selectedFile;

    const selCard = document.getElementById('upload-selected-card');

    const progCard = document.getElementById('upload-progress-card');

    const errBox = document.getElementById('upload-error-box');

    const statusText = document.getElementById('upload-progress-current-text');



    if (selCard) selCard.style.display = 'none';

    if (errBox) errBox.style.display = 'none';

    if (progCard) progCard.style.display = 'block';



    const stages = [

        { id: 'prog-stage-1', text: 'ÔÜí 1. Uploading payload stream safely...' },

        { id: 'prog-stage-2', text: '­ƒöì 2. Validating DOS header & PE format...' },

        { id: 'prog-stage-3', text: '­ƒöæ 3. Calculating SHA-256, SHA-1, MD5 hashes...' },

        { id: 'prog-stage-4', text: '­ƒº® 4. Parsing PE headers, sections & entropy...' },

        { id: 'prog-stage-5', text: '­ƒöî 5. Extracting APIs, strings & threat indicators...' },

        { id: 'prog-stage-6', text: '­ƒñû 6. Running YARA & synthesizing AI assessment...' },

    ];



    let currentStageIndex = 0;

    const progressTimer = setInterval(() => {

        if (currentStageIndex < stages.length) {

            const st = stages[currentStageIndex];

            if (statusText) statusText.textContent = st.text.replace(/^[^\s]+\s/, '');

            const stageEl = document.getElementById(st.id);

            if (stageEl) stageEl.style.color = 'var(--accent-cyan)';

            currentStageIndex++;

        }

    }, 450);



    const formData = new FormData();

    formData.append('file', file);



    try {

        const response = await fetchWithAuth(`/api/analyses?language=${state.currentLanguage}`, {

            method: 'POST',

            body: formData,

        });



        clearInterval(progressTimer);



        if (!response.ok) {

            let errorDetail = 'Analysis request failed.';

            try {

                const errData = await response.json();

                errorDetail = errData.detail || errorDetail;

            } catch (_) {}

            throw new Error(errorDetail);

        }



        const resData = await response.json();

        const analysisData = resData.data || resData;



        state.sampleData = analysisData;

        renderSampleData(analysisData);

        clearSelectedFile();

        switchTab('analysis');



    } catch (err) {

        clearInterval(progressTimer);

        if (progCard) progCard.style.display = 'none';

        if (selCard) selCard.style.display = 'block';

        if (errBox) {

            errBox.textContent = `Static Analysis Error: ${err.message}`;

            errBox.style.display = 'block';

        }

    }

}



/**

 * Load Safe Synthetic Sample

 */

function loadDemoSample() {

    const demoData = {

        analysis_id: "ANL-DEMO-CBE01",

        filename: "commercial_banking_agent.exe",

        language: state.currentLanguage,

        file_information: {

            filename: "commercial_banking_agent.exe",

            file_size: 48128,

            file_kind: "EXE",

            machine_type: "x64",

            compile_time: "2026-02-16 14:22:00"

        },

        hashes: {

            sha256: "3aca6c684a39c9ecaf3de614663d9c2240be7869d5ed5642b49140034ca9db9e",

            sha1: "b5d848777ff7528e10408bd3725c898c8c7d3db1",

            md5: "eef52d1656582cb18a4f2deba3aed525"

        },

        pe_information: {

            subsystem: "Windows GUI",

            machine_architecture: "x64",

            characteristics: 0x0102,

            entry_point: "0x000024B0",

            image_base: "0x00400000",

            compile_time: "2026-02-16 14:22:00"

        },

        sections: {

            total_sections: 3,

            has_wx_sections: true,

            sections: [

                { name: ".text", virtual_address: 4096, virtual_size: 16384, raw_size: 16384, entropy: 6.42, characteristics: "0x60000020" },

                { name: ".packed", virtual_address: 20480, virtual_size: 24576, raw_size: 24576, entropy: 7.74, characteristics: "0xE0000020" },

                { name: ".rsrc", virtual_address: 45056, virtual_size: 7168, raw_size: 7168, entropy: 4.15, characteristics: "0x40000040" }

            ]

        },

        entropy: {

            file_entropy: 7.48,

            classification: "VERY_HIGH"

        },

        strings: {

            urls: ["https://auth.telecom.et/login.php", "https://threat-c2.net/payload.bin"],

            ip_addresses: ["196.188.120.10", "10.0.0.1"],

            registry_paths: ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],

            commands: ["cmd.exe /c powershell -enc JABz..."]

        },

        imports: {

            total_imports: 4,

            imports: [

                { dll: "KERNEL32.dll", api: "VirtualAlloc", category: "MEMORY", risk_relevance: "MEDIUM" },

                { dll: "KERNEL32.dll", api: "VirtualProtect", category: "MEMORY", risk_relevance: "MEDIUM" },

                { dll: "WININET.dll", api: "InternetOpenA", category: "NETWORK", risk_relevance: "HIGH" },

                { dll: "ADVAPI32.dll", api: "RegSetValueExA", category: "REGISTRY", risk_relevance: "LOW" }

            ]

        },

        indicators: {

            total_indicators: 3,

            indicators: [

                {

                    id: "IND-STR-001",

                    name: "Writable and Executable (W+X) Section Detected",

                    category: "PE_STRUCTURE",

                    severity: "HIGH",

                    evidence: "Section '.packed' has simultaneous W+X permissions",

                    confidence: 1.0,

                    explanation: "Violates standard DEP policies; often used for runtime unpacking."

                },

                {

                    id: "IND-MEM-001",

                    name: "Correlated Memory Staging & Permission Alteration",

                    category: "MEMORY",

                    severity: "HIGH",

                    evidence: "VirtualAlloc + VirtualProtect APIs imported",

                    confidence: 0.95,

                    explanation: "Allows allocating and changing memory pages to executable at runtime."

                },

                {

                    id: "IND-NET-001",

                    name: "Correlated Network Endpoints & Egress Primitives",

                    category: "NETWORK",

                    severity: "HIGH",

                    evidence: "URL extracted + InternetOpenA API imported",

                    confidence: 0.9,

                    explanation: "Indicates network connectivity capability."

                }

            ]

        },

        threat_score: {

            score: 85,

            risk_level: "CRITICAL"

        },

        ethiopian_context: {

            environment: "FINANCIAL",

            relevance: "CRITICAL",

            reason: "Memory manipulation and domestic Ethiopian telecom endpoints present critical risk to financial infrastructure."

        },

        ai_assessment: {

            assessment: "CRITICAL",

            confidence: "HIGH",

            summary: "Static analysis indicates a CRITICAL threat posture with packed sections, in-memory page permission modifications, and network egress capabilities targeting Ethiopian banking context.",

            key_findings: [

                "Heuristic Threat Score: 85/100 [CRITICAL].",

                "Direct reference to Ethiopian domestic network infrastructure (telecom.et) identified."

            ],

            possible_benign_explanations: ["Legitimate commercial software packer or DRM protection."],

            recommended_investigation: ["Execute in isolated sandbox to observe live network connections."],

            limitations: ["Static analysis evaluates capabilities without live execution."]

        }

    };



    state.sampleData = demoData;

    renderSampleData(demoData);

    switchTab('analysis');

}



function renderSampleData(data) {

    if (!data) {

        const emptyState = document.getElementById('analysis-empty-state');

        const contentWrap = document.getElementById('analysis-content-wrapper');

        if (emptyState) emptyState.style.display = 'block';

        if (contentWrap) contentWrap.style.display = 'none';

        return;

    }



    state.sampleData = data;

    state.activeAnalysisId = data.analysis_id || data.id;



    // Show Content and Hide Empty State

    const emptyState = document.getElementById('analysis-empty-state');

    const contentWrap = document.getElementById('analysis-content-wrapper');

    if (emptyState) emptyState.style.display = 'none';

    if (contentWrap) contentWrap.style.display = 'block';



    // Show Sample Badge in Topbar

    const sampleBadge = document.getElementById('current-sample-badge');

    const sampleName = document.getElementById('current-sample-name');

    if (sampleBadge && sampleName) {

        sampleBadge.style.display = 'flex';

        sampleName.textContent = data.filename || 'sample.exe';

    }



    // 1. Compact File Identity Section

    const fi = data.file_information || data.file || {};

    const hashes = data.hashes || {};

    const ts = data.threat_score || data.risk || data.risk_score || { score: 0, risk_level: "LOW" };

    const pe = data.pe_information || data.pe || {};

    const sec = data.sections || { sections: [] };

    const sectionsList = Array.isArray(sec) ? sec : (sec.sections || []);

    const imp = data.imports || { imports: [] };

    const importsList = Array.isArray(imp) ? imp : (imp.imports || []);

    const iocData = data.iocs || { items: [] };

    const iocItems = Array.isArray(iocData) ? iocData : (iocData.items || []);

    const yaraData = data.yara_matches || { matches: [] };

    const yaraList = Array.isArray(yaraData) ? yaraData : (yaraData.matches || []);

    const riskFactors = data.risk_factors || [];



    const fnEl = document.getElementById('ov-filename');

    if (fnEl) fnEl.textContent = fi.filename || data.filename || 'Not available';



    const sha256Val = hashes.sha256 || data.sha256 || 'Not available';

    const shaShortEl = document.getElementById('ov-sha256-short');

    if (shaShortEl) shaShortEl.textContent = sha256Val.length > 16 ? `${sha256Val.substring(0, 16)}...` : sha256Val;



    const shaFullEl = document.getElementById('ov-sha256');

    if (shaFullEl) shaFullEl.textContent = sha256Val;



    const sha1El = document.getElementById('ov-sha1');

    if (sha1El) sha1El.textContent = hashes.sha1 || data.sha1 || 'Not available';



    const md5El = document.getElementById('ov-md5');

    if (md5El) md5El.textContent = hashes.md5 || data.md5 || 'Not available';



    const archTypeEl = document.getElementById('ov-arch-type');

    if (archTypeEl) archTypeEl.textContent = `${fi.machine_type || fi.architecture || data.architecture || 'x64'} ÔÇó ${fi.file_kind || fi.file_type || data.file_type || 'Windows PE'}`;



    const sizeEl = document.getElementById('ov-filesize');

    if (sizeEl) sizeEl.textContent = `${((fi.file_size || data.size || 0) / 1024).toFixed(1)} KB`;



    const anIdEl = document.getElementById('ov-analysis-id');

    if (anIdEl) anIdEl.textContent = data.analysis_id || 'ANL-000000';



    const statusBadge = document.getElementById('ov-status-badge');

    if (statusBadge) {

        statusBadge.textContent = data.status || 'COMPLETED';

        statusBadge.className = `badge ${(data.status === 'FAILED' ? 'badge-crit' : 'badge-low')}`;

    }



    const compileDateEl = document.getElementById('ov-compile-date');

    if (compileDateEl) {

        compileDateEl.textContent = pe.compile_time || fi.compile_time || fi.timestamp || 'Not available';

    }



    // 2. Automated Threat Risk Score & Gauge

    const scoreVal = ts.score !== undefined ? ts.score : (data.risk_score || 0);

    const calculatedLevel = scoreVal >= 75 ? 'CRITICAL' : (scoreVal >= 50 ? 'HIGH' : (scoreVal >= 25 ? 'MEDIUM' : 'LOW'));

    renderThreatGauge(scoreVal, ts.risk_level || calculatedLevel);



    // 3. "WHY THIS SCORE?" Risk Contributing Factors Breakdown

    const rfTbody = document.getElementById('ov-risk-factors-tbody');

    const factorsBadge = document.getElementById('ov-factors-count-badge');

    const factorsSum = document.getElementById('ov-factors-sum-text');



    if (factorsBadge) factorsBadge.textContent = `${riskFactors.length} FACTORS`;

    if (factorsSum) factorsSum.textContent = `Calculated Index: ${scoreVal}/100`;



    if (rfTbody) {

        if (riskFactors.length > 0) {

            rfTbody.innerHTML = riskFactors.map(rf => `

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td><strong>${escapeHtml(rf.name)}</strong></td>

                    <td><span class="badge badge-rule">${escapeHtml(rf.category || 'HEURISTIC')}</span></td>

                    <td><span class="badge ${getRiskBadgeClass(rf.severity || 'LOW')}">${escapeHtml(rf.severity || 'LOW')}</span></td>

                    <td style="text-align: right; font-weight: 700; color: var(--accent-cyan);">+${rf.weight}</td>

                </tr>

            `).join('');

        } else {

            rfTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="4" class="empty-state-cell">No contributing risk factors recorded. Standard clean baseline.</td></tr>`;

        }

    }



    // 4. 7 Threat Evidence Quick Breakdown Cards

    const suspApisCount = importsList.filter(i => (i.risk_relevance || '').toUpperCase() in { HIGH: 1, CRITICAL: 1, MEDIUM: 1 }).length;

    const suspStringsCount = (data.strings && data.strings.suspicious_count !== undefined) ? data.strings.suspicious_count : (Array.isArray(data.strings) ? data.strings.filter(s => s.suspicious || (s.severity || '').toUpperCase() in { HIGH: 1, CRITICAL: 1 }).length : 0);

    const netIocsCount = iocItems.filter(i => (i.type || '').toUpperCase() in { DOMAIN: 1, IP: 1, URL: 1, IP_ADDRESS: 1 }).length;

    const regIocsCount = iocItems.filter(i => (i.type || '').toUpperCase() in { REGISTRY: 1, REGISTRY_KEY: 1, REGISTRY_PATH: 1 }).length;

    const highEntropyCount = sectionsList.filter(s => (s.entropy || 0) >= 6.8).length;

    const packingCount = sectionsList.filter(s => (s.name || '').includes('pack') || (s.name || '').includes('upx') || (s.entropy || 0) >= 7.2).length;

    const persistenceCount = importsList.filter(i => (i.category || '').toUpperCase() === 'REGISTRY' || (i.category || '').toUpperCase() === 'PERSISTENCE').length;



    const setEvCard = (countId, badgeId, count, highThresh = 1) => {

        const cEl = document.getElementById(countId);

        const bEl = document.getElementById(badgeId);

        if (cEl) cEl.textContent = count;

        if (bEl) {

            const sev = count >= highThresh ? (count > highThresh * 2 ? 'HIGH' : 'SUSPICIOUS') : 'LOW';

            bEl.textContent = sev;

            bEl.className = `badge ${getRiskBadgeClass(sev)}`;

        }

    };



    setEvCard('ev-apis-count', 'ev-apis-badge', suspApisCount, 2);

    setEvCard('ev-strings-count', 'ev-strings-badge', suspStringsCount, 3);

    setEvCard('ev-net-count', 'ev-net-badge', netIocsCount, 1);

    setEvCard('ev-reg-count', 'ev-reg-badge', regIocsCount, 1);

    setEvCard('ev-entropy-count', 'ev-entropy-badge', highEntropyCount, 1);

    setEvCard('ev-packing-count', 'ev-packing-badge', packingCount, 1);

    setEvCard('ev-persistence-count', 'ev-persistence-badge', persistenceCount, 1);



    // 5. PE Structure & Sections Table

    const peSubsystemEl = document.getElementById('pe-subsystem');

    if (peSubsystemEl) peSubsystemEl.textContent = pe.subsystem || 'Windows GUI';



    const peEntryEl = document.getElementById('pe-entry-point');

    if (peEntryEl) peEntryEl.textContent = pe.entry_point || '0x00001000';



    const peImageEl = document.getElementById('pe-image-base');

    if (peImageEl) peImageEl.textContent = pe.image_base || '0x00400000';



    const secCountBadge = document.getElementById('pe-sections-count-badge');

    if (secCountBadge) secCountBadge.textContent = `${sectionsList.length} SECTIONS`;



    const secTbody = document.getElementById('pe-sections-tbody');

    if (secTbody) {

        if (sectionsList.length > 0) {

            secTbody.innerHTML = sectionsList.map(s => {

                const entVal = Number(s.entropy || 0);

                const entInterp = entVal >= 7.0 ? 'High Entropy (Packed)' : (entVal >= 6.0 ? 'Moderately Unusual' : 'Normal');

                const entBadgeClass = entVal >= 7.0 ? 'badge-crit' : (entVal >= 6.0 ? 'badge-susp' : 'badge-low');

                return `

                    <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                        <td><strong>${escapeHtml(s.name)}</strong></td>

                        <td class="font-mono">${typeof s.virtual_address === 'number' ? '0x' + s.virtual_address.toString(16).toUpperCase() : escapeHtml(s.virtual_address)}</td>

                        <td>${s.virtual_size ? `${(s.virtual_size / 1024).toFixed(1)} KB` : '0 KB'}</td>

                        <td>${s.raw_size ? `${(s.raw_size / 1024).toFixed(1)} KB` : '0 KB'}</td>

                        <td class="font-mono"><strong>${entVal.toFixed(2)}</strong></td>

                        <td><span class="badge ${entBadgeClass}">${entInterp}</span></td>

                        <td><span class="font-mono" style="font-size: 10px;">${escapeHtml(s.characteristics || '')}</span></td>

                    </tr>

                `;

            }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

        } else {

            secTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-table-msg">No sections data available for this binary.</td></tr>`;

        }

    }



    // 6. Import & API Intelligence Table

    const impBadge = document.getElementById('imports-count-badge');

    if (impBadge) impBadge.textContent = `${importsList.length} IMPORTS`;



    const impTbody = document.getElementById('imports-tbody');

    if (impTbody) {

        if (importsList.length > 0) {

            impTbody.innerHTML = importsList.map(i => `

                <tr style="cursor: pointer;" data-type="api" data-api="${escapeHtml(i.api)}" data-dll="${escapeHtml(i.dll)}" data-category="${escapeHtml(i.category || 'GENERAL')}" data-risk="${escapeHtml(i.risk_relevance || 'LOW')}" data-description="Imported API function from ${escapeHtml(i.dll)}">

                    <td class="font-mono">${escapeHtml(i.dll)}</td>

                    <td><strong>${escapeHtml(i.api)}</strong></td>

                    <td><span class="badge badge-rule">${escapeHtml(i.category || 'GENERAL')}</span></td>

                    <td><span class="badge ${getRiskBadgeClass(i.risk_relevance || 'LOW')}">${escapeHtml(i.risk_relevance || 'LOW')}</span></td>

                </tr>

            `).join('');

        } else {

            impTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="4" class="empty-table-msg">No imported Windows APIs detected.</td></tr>`;

        }

    }



    // 7. String Intelligence Summary & Top Strings

    const strObj = data.strings || {};

    const totalStr = strObj.total_strings || strObj.total || 0;

    const suspStr = strObj.suspicious_count || (Array.isArray(strObj) ? strObj.filter(s => s.suspicious).length : 0);

    const urlsStr = (strObj.urls || []).length;

    const ipsStr = (strObj.ip_addresses || []).length;

    const cmdsStr = (strObj.commands || []).length;

    const regStr = (strObj.registry_paths || []).length;



    animateCounter('ov-str-total', totalStr);

    animateCounter('ov-str-susp', suspStr);

    animateCounter('ov-str-urls', urlsStr);

    animateCounter('ov-str-ips', ipsStr);

    animateCounter('ov-str-cmds', cmdsStr);

    animateCounter('ov-str-reg', regStr);



    const topStrTbody = document.getElementById('ov-top-strings-tbody');

    if (topStrTbody) {

        const sampleStrings = Array.isArray(strObj) ? strObj : (strObj.strings || []);

        if (sampleStrings.length > 0) {

            topStrTbody.innerHTML = sampleStrings.slice(0, 5).map(s => `

                <tr style="cursor: pointer;" data-type="string" data-value="${escapeHtml(s.value || s)}" data-category="${escapeHtml(s.category || s.type || 'STRING')}" data-severity="${escapeHtml(s.severity || 'LOW')}" data-encoding="${escapeHtml(s.encoding || 'ASCII')}" data-reason="${escapeHtml(s.reason || 'Extracted ASCII / Unicode string artifact')}">

                    <td class="font-mono" style="word-break: break-all; max-width: 260px;">${escapeHtml(s.value || s)}</td>

                    <td><span class="badge badge-rule">${escapeHtml(s.category || s.type || 'GENERAL')}</span></td>

                    <td><span class="badge ${getRiskBadgeClass(s.severity || 'LOW')}">${escapeHtml(s.severity || 'LOW')}</span></td>

                    <td>${escapeHtml(s.reason || 'Extracted literal')}</td>

                </tr>

            `).join('');

        } else {

            topStrTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="4" class="empty-state-cell">No suspicious strings recorded.</td></tr>`;

        }

    }



    // 8. Indicators of Compromise (IOCs) Table

    const iocBadge = document.getElementById('ov-iocs-count-badge');

    if (iocBadge) iocBadge.textContent = `${iocItems.length} IOCs`;



    const iocTbody = document.getElementById('ov-iocs-tbody');

    if (iocTbody) {

        if (iocItems.length > 0) {

            iocTbody.innerHTML = iocItems.map(ioc => `

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td><span class="badge badge-rule">${escapeHtml(ioc.type)}</span></td>

                    <td class="font-mono" style="word-break: break-all;">${escapeHtml(ioc.value)}</td>

                    <td>${escapeHtml(ioc.source || 'STATIC_ANALYSIS')}</td>

                    <td>${ioc.confidence ? `${Math.round(ioc.confidence * 100)}%` : '100%'}</td>

                    <td style="text-align: right;">

                        <button class="btn-secondary" data-action="copy-ioc" data-value="${escapeHtml(ioc.value)}" style="font-size: 9px; padding: 2px 6px;">­ƒôï Copy</button>

                    </td>

                </tr>

            `).join('');

        } else {

            iocTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="5" class="empty-state-cell">No active Indicators of Compromise extracted.</td></tr>`;

        }

    }



    // 9. YARA Detections & MITRE ATT&CK Mapping

    const yaraBadge = document.getElementById('ov-yara-count-badge');

    if (yaraBadge) yaraBadge.textContent = `${yaraList.length} MATCHES`;



    const yaraTbody = document.getElementById('ov-yara-tbody');

    if (yaraTbody) {

        if (yaraList.length > 0) {

            yaraTbody.innerHTML = yaraList.map(ym => `

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td><strong style="color: var(--sev-high);">${escapeHtml(ym.rule_name)}</strong></td>

                    <td>${escapeHtml(ym.namespace || 'default')}</td>

                    <td>${escapeHtml(ym.description || (Array.isArray(ym.tags) ? ym.tags.join(', ') : ym.tags) || 'Matched rule pattern')}</td>

                </tr>

            `).join('');

        } else {

            yaraTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="3" class="empty-state-cell">No YARA signature matches detected. Clean scan.</td></tr>`;

        }

    }



    // MITRE ATT&CK Mapping

    const mitreList = data.mitre_attack || [

        { technique_id: "T1059", technique_name: "Command and Scripting Interpreter", evidence: "Command execution primitives found in imports/strings" },

        { technique_id: "T1105", technique_name: "Ingress Tool Transfer", evidence: "Network downloader APIs observed" }

    ];

    const mitreBadge = document.getElementById('ov-mitre-count-badge');

    if (mitreBadge) mitreBadge.textContent = `${mitreList.length} TECHNIQUES`;



    const mitreTbody = document.getElementById('ov-mitre-tbody');

    if (mitreTbody) {

        if (mitreList.length > 0) {

            mitreTbody.innerHTML = mitreList.map(m => `

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td class="font-mono" style="color: var(--accent-cyan);"><strong>${escapeHtml(m.technique_id)}</strong></td>

                    <td><strong>${escapeHtml(m.technique_name || m.tactic || 'Technique')}</strong></td>

                    <td>${escapeHtml(m.evidence || '')}</td>

                </tr>

            `).join('');

        } else {

            mitreTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="3" class="empty-state-cell">No MITRE ATT&CK technique alignments identified.</td></tr>`;

        }

    }



    // 10. AI Security Analyst Interpretation

    const ai = data.ai_assessment || {};

    const aiSumEl = document.getElementById('ov-ai-summary');

    if (aiSumEl) aiSumEl.textContent = ai.summary || 'Static analysis complete. Evaluation reveals capabilities based on headers and APIs.';



    const aiConfBadge = document.getElementById('ov-ai-conf-badge');

    if (aiConfBadge) aiConfBadge.textContent = `CONFIDENCE: ${ai.confidence || 'MEDIUM'}`;



    renderBulletList('ov-ai-findings-list', ai.key_findings || [`Assigned heuristic risk level: ${calculatedLevel} (Score: ${scoreVal}/100)`]);

    renderBulletList('ov-ai-recs-list', ai.recommended_investigation || ['Verify binary hash across enterprise EDR endpoints.']);



    // 11. Case Management & Notes

    const caseInfo = data.case_info || {};

    const caseIdInput = document.getElementById('case-id-input');

    if (caseIdInput) caseIdInput.value = caseInfo.case_id || `CASE-${(data.analysis_id || '000').slice(-6)}`;



    const caseInvestigatorInput = document.getElementById('case-investigator-input');

    if (caseInvestigatorInput) caseInvestigatorInput.value = caseInfo.investigator || (state.currentUser ? state.currentUser.username : 'SOC Analyst');



    const caseStatusSelect = document.getElementById('case-status-select');

    if (caseStatusSelect && caseInfo.case_status) caseStatusSelect.value = caseInfo.case_status;



    const casePrioritySelect = document.getElementById('case-priority-select');

    if (casePrioritySelect && caseInfo.case_priority) casePrioritySelect.value = caseInfo.case_priority;



    renderAnalystNotesList(data.notes || []);

}



/**

 * Jump to Specific Analysis Evidence Stage

 */

function jumpToAnalysisStage(stageKey) {

    if (stageKey === 'strings') {

        switchTab('strings');

        return;

    }

    const secMap = {

        'identity': 'sec-identity',

        'hashes': 'sec-hashes',

        'pe-headers': 'sec-identity',

        'sections': 'sec-sections',

        'imports': 'sec-imports',

        'iocs': 'sec-iocs',

        'risk-engine': 'sec-risk-engine',

        'ai-analyst': 'sec-ai-analyst'

    };

    const targetId = secMap[stageKey] || stageKey;

    const targetEl = document.getElementById(targetId);

    if (targetEl) {

        targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });

        targetEl.style.transition = 'outline 0.3s ease';

        targetEl.style.outline = '2px solid var(--accent-cyan)';

        setTimeout(() => { targetEl.style.outline = 'none'; }, 1600);

    }

}



/**

 * Copy Full SHA-256 Hash

 */

function copyAnalysisHash() {

    const hash = (state.sampleData && state.sampleData.hashes && state.sampleData.hashes.sha256) || (state.sampleData && state.sampleData.sha256);

    if (hash) {

        navigator.clipboard.writeText(hash);

        showSocNotification('Copied Hash', 'SHA-256 copied to clipboard.', 'success');

    }

}



/**

 * Copy All IOCs to Clipboard

 */

function copyAllIOCs() {

    if (!state.sampleData) return;

    const iocData = state.sampleData.iocs || {};

    const iocItems = Array.isArray(iocData) ? iocData : (iocData.items || []);

    if (!iocItems.length) {

        showSocNotification('No IOCs', 'No IOCs available to copy.', 'warning');

        return;

    }

    const txt = iocItems.map(i => `${i.type}: ${i.value}`).join('\n');

    navigator.clipboard.writeText(txt);

    showSocNotification('Copied IOCs', `${iocItems.length} IOCs copied to clipboard.`, 'success');

}



/**

 * Export IOCs as CSV File

 */

function exportIOCsAsCSV() {

    if (!state.sampleData) return;

    const iocData = state.sampleData.iocs || {};

    const iocItems = Array.isArray(iocData) ? iocData : (iocData.items || []);

    if (!iocItems.length) {

        alert('No IOCs available to export.');

        return;

    }

    let csv = 'Type,Value,Source,Confidence\n';

    iocItems.forEach(i => {

        csv += `"${i.type}","${(i.value || '').replace(/"/g, '""')}","${i.source || 'STATIC_ANALYSIS'}","${i.confidence || 1.0}"\n`;

    });

    const blob = new Blob([csv], { type: 'text/csv' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = `IOCs_${state.sampleData.analysis_id || 'analysis'}.csv`;

    a.click();

    URL.revokeObjectURL(url);

}



/**

 * Ask AI Contextual Investigation

 */

function askAiPrompt(promptText) {

    const input = document.getElementById('ask-ai-input');

    if (input) {

        input.value = promptText;

        executeAskAi();

    }

}



async function executeAskAi() {

    const input = document.getElementById('ask-ai-input');

    const respBox = document.getElementById('ask-ai-response-box');

    const btn = document.getElementById('btn-ask-ai-send');

    if (!input || !respBox) return;



    const question = input.value.trim();

    if (!question) return;



    if (!state.sampleData || !state.sampleData.analysis_id) {

        respBox.style.display = 'block';

        respBox.innerHTML = '<span style="color: var(--sev-high);">No analysis loaded to investigate.</span>';

        return;

    }



    respBox.style.display = 'block';

    respBox.innerHTML = '<span style="color: var(--accent-cyan);">­ƒñû AI Security Analyst analyzing evidence...</span>';

    if (btn) btn.disabled = true;



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(state.sampleData.analysis_id)}/ask-ai`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ question: question, language: state.currentLanguage || 'en' })

        });

        if (!res.ok) throw new Error('AI investigation service unavailable.');

        const data = await res.json();

        respBox.innerHTML = `

            <div style="font-weight: 700; color: var(--accent-cyan); margin-bottom: 6px;">­ƒñû Grounded Analysis Insight:</div>

            <div style="color: var(--text-primary); line-height: 1.6;">${escapeHtml(data.answer)}</div>

            <div style="font-size: 10px; color: var(--text-muted); margin-top: 8px;">Confidence: ${escapeHtml(data.confidence || 'HIGH')} ÔÇó ${escapeHtml(data.disclaimer || '')}</div>

        `;

    } catch (err) {

        respBox.innerHTML = `<span style="color: var(--sev-high);">AI Query Failed: ${escapeHtml(err.message)}</span>`;

    } finally {

        if (btn) btn.disabled = false;

    }

}



/**

 * Analyst Notes Management

 */

function renderAnalystNotesList(notes) {

    const container = document.getElementById('analyst-notes-list');

    const badge = document.getElementById('notes-count-badge');

    if (badge) badge.textContent = `${notes.length} NOTES`;

    if (!container) return;



    if (!notes.length) {

        container.innerHTML = '<div class="empty-state-cell">No investigation notes recorded for this analysis yet.</div>';

        return;

    }



    container.innerHTML = notes.map(n => `

        <div class="note-item">

            <div class="note-header">

                <span class="note-author">­ƒæñ ${escapeHtml(n.author || 'Analyst')}</span>

                <div style="display: flex; gap: 6px; align-items: center;">

                    <span class="note-tag-badge badge badge-rule">${escapeHtml(n.tag || 'OBSERVATION')}</span>

                    <button class="btn-secondary" data-action="delete-note" data-note-id="${n.id}" style="font-size: 8px; padding: 1px 4px; color: var(--sev-crit);">Ô£ò</button>

                </div>

            </div>

            <div class="note-content">${escapeHtml(n.content)}</div>

            <div style="font-size: 9px; color: var(--text-dim); text-align: right;">${n.created_at ? n.created_at.substring(0, 19).replace('T', ' ') : ''}</div>

        </div>

    `).join('');

}



async function addAnalystNote() {

    const input = document.getElementById('note-content-input');

    const tagSelect = document.getElementById('note-tag-select');

    if (!input || !input.value.trim() || !state.sampleData) return;



    const content = input.value.trim();

    const tag = tagSelect ? tagSelect.value : 'OBSERVATION';



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(state.sampleData.analysis_id)}/notes`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ content: content, tag: tag })

        });

        if (!res.ok) throw new Error('Failed to record note.');

        const newNote = await res.json();

        if (!state.sampleData.notes) state.sampleData.notes = [];

        state.sampleData.notes.unshift(newNote);

        renderAnalystNotesList(state.sampleData.notes);

        input.value = '';

        showSocNotification('Note Saved', 'Analyst observation persisted to database.', 'success');

    } catch (err) {

        showSocNotification('Note Error', err.message, 'warning');

    }

}



function handleAnalystNotesClick(event) {
    const btn = event.target.closest('[data-action="delete-note"]');
    if (!btn) return;
    const noteId = parseInt(btn.dataset.noteId, 10);
    if (!isNaN(noteId)) {
        deleteAnalystNote(noteId);
    }
}

async function deleteAnalystNote(noteId) {

    if (!state.sampleData) return;

    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(state.sampleData.analysis_id)}/notes/${noteId}`, {

            method: 'DELETE'

        });

        if (!res.ok) throw new Error('Could not delete note.');

        state.sampleData.notes = (state.sampleData.notes || []).filter(n => n.id !== noteId);

        renderAnalystNotesList(state.sampleData.notes);

        showSocNotification('Note Deleted', 'Note removed from analysis record.', 'info');

    } catch (err) {

        showSocNotification('Delete Error', err.message, 'warning');

    }

}



async function saveCaseInfo() {

    if (!state.sampleData) return;

    const caseId = document.getElementById('case-id-input') ? document.getElementById('case-id-input').value : null;

    const caseStatus = document.getElementById('case-status-select') ? document.getElementById('case-status-select').value : null;

    const casePriority = document.getElementById('case-priority-select') ? document.getElementById('case-priority-select').value : null;



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(state.sampleData.analysis_id)}/case`, {

            method: 'PATCH',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ case_id: caseId, case_status: caseStatus, case_priority: casePriority })

        });

        if (!res.ok) throw new Error('Could not update case tracking.');

        showSocNotification('Case Updated', 'Case status & priority saved successfully.', 'success');

    } catch (err) {

        showSocNotification('Case Error', err.message, 'warning');

    }

}



/**

 * Binary Analysis Comparison Modal

 */

async function openCompareModal() {

    const modal = document.getElementById('compare-analysis-modal');

    const select = document.getElementById('compare-target-select');

    if (!modal) return;

    modal.style.display = 'flex';



    if (select) {

        select.innerHTML = '<option value="">-- Choose analysis from history --</option>';

        try {

            const res = await fetchWithAuth('/api/analyses?limit=50');

            if (res.ok) {

                const data = await res.json();

                const items = data.items || [];

                const currentId = state.sampleData ? state.sampleData.analysis_id : '';

                items.filter(it => it.analysis_id !== currentId).forEach(it => {

                    const opt = document.createElement('option');

                    opt.value = it.analysis_id;

                    opt.textContent = `${it.filename} (Score: ${it.risk_score}, ID: ${it.analysis_id})`;

                    select.appendChild(opt);

                });

            }

        } catch (e) {

            console.warn('Failed to populate comparison options', e);

        }

    }

}



function closeCompareModal() {

    const modal = document.getElementById('compare-analysis-modal');

    if (modal) modal.style.display = 'none';

}



async function executeAnalysisComparison() {

    const select = document.getElementById('compare-target-select');

    const results = document.getElementById('compare-results-container');

    if (!select || !select.value || !state.sampleData || !results) return;



    const id1 = state.sampleData.analysis_id;

    const id2 = select.value;



    try {

        const res = await fetchWithAuth(`/api/analyses/compare?id1=${encodeURIComponent(id1)}&id2=${encodeURIComponent(id2)}`);

        if (!res.ok) throw new Error('Failed to compute comparison.');

        const data = await res.json();



        results.style.display = 'block';



        const sa = data.sample_a;

        const sb = data.sample_b;



        document.getElementById('cmp-a-title').textContent = `Current: ${sa.analysis_id}`;

        document.getElementById('cmp-a-file').textContent = sa.filename;

        document.getElementById('cmp-a-score').textContent = `${sa.risk_score} (${sa.risk_level})`;

        document.getElementById('cmp-a-arch').textContent = `${sa.architecture} ÔÇó ${sa.file_type}`;

        document.getElementById('cmp-a-apis').textContent = sa.suspicious_apis;

        document.getElementById('cmp-a-strings').textContent = sa.suspicious_strings;

        document.getElementById('cmp-a-entropy').textContent = sa.max_section_entropy;

        document.getElementById('cmp-a-iocs').textContent = sa.total_iocs;



        document.getElementById('cmp-b-title').textContent = `Target: ${sb.analysis_id}`;

        document.getElementById('cmp-b-file').textContent = sb.filename;

        document.getElementById('cmp-b-score').textContent = `${sb.risk_score} (${sb.risk_level})`;

        document.getElementById('cmp-b-arch').textContent = `${sb.architecture} ÔÇó ${sb.file_type}`;

        document.getElementById('cmp-b-apis').textContent = sb.suspicious_apis;

        document.getElementById('cmp-b-strings').textContent = sb.suspicious_strings;

        document.getElementById('cmp-b-entropy').textContent = sb.max_section_entropy;

        document.getElementById('cmp-b-iocs').textContent = sb.total_iocs;



        const delta = data.differences.score_delta;

        const deltaEl = document.getElementById('compare-delta-summary');

        if (deltaEl) {

            deltaEl.innerHTML = `<strong>Risk Delta:</strong> ${Math.abs(delta)} pts (${delta > 0 ? 'Current is higher risk' : (delta < 0 ? 'Target is higher risk' : 'Identical threat posture')}) ÔÇó Architecture: ${data.differences.same_architecture ? 'MATCH' : 'DIFFERENT'}`;

        }

    } catch (err) {

        showSocNotification('Comparison Failed', err.message, 'warning');

    }

}



/**

 * Export Security Analysis Report in requested format

 */

async function exportCurrentReport(format) {

    if (!state.sampleData || !state.sampleData.analysis_id) {

        alert('No analysis sample is currently loaded to export.');

        return;

    }

    const analysisId = state.sampleData.analysis_id;

    const lang = state.currentLanguage || 'en';



    showSocNotification('Generating Report', `Preparing ${format.toUpperCase()} report...`, 'info');



    try {

        const reportUrl = `/api/analyses/${encodeURIComponent(analysisId)}/report?format=${format}&language=${lang}`;

        const res = await fetchWithAuth(reportUrl);

        if (!res.ok) throw new Error(`Report generation failed (${res.status}).`);



        if (format === 'json') {

            const blob = await res.blob();

            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');

            a.href = url;

            a.download = `Analysis_${analysisId}.json`;

            a.click();

            URL.revokeObjectURL(url);

        } else if (format === 'html') {

            const htmlText = await res.text();

            const blob = new Blob([htmlText], { type: 'text/html' });

            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');

            a.href = url;

            a.download = `Report_${analysisId}.html`;

            a.click();

            URL.revokeObjectURL(url);

        } else if (format === 'markdown' || format === 'text') {

            const txt = await res.text();

            const blob = new Blob([txt], { type: 'text/plain' });

            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');

            a.href = url;

            a.download = `Report_${analysisId}.${format === 'markdown' ? 'md' : 'txt'}`;

            a.click();

            URL.revokeObjectURL(url);

        }

        showSocNotification('Report Ready', `${format.toUpperCase()} report exported successfully.`, 'success');

    } catch (err) {

        showSocNotification('Export Failed', `Report generation failed: ${err.message}`, 'danger');

    }

}



/**

 * Load and Render Analysis History

 */

async function loadAnalysisHistory() {

    const tbody = document.getElementById('history-tbody');

    const badge = document.getElementById('history-count-badge');

    if (tbody) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">Loading analysis records from database...</td></tr>`;

    }



    try {

        const response = await fetchWithAuth('/api/analyses?limit=100');

        if (!response.ok) {

            throw new Error('Failed to load analysis history from server.');

        }



        const data = await response.json();

        state.historyList = data.items || [];



        if (badge) {

            badge.textContent = `${data.total || state.historyList.length} analyses`;

        }



        filterHistoryTable();



    } catch (err) {

        if (tbody) {

            tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell" style="color: var(--sev-high);">Error loading history: ${err.message}</td></tr>`;

        }

    }

}



function filterHistoryTable() {

    const tbody = document.getElementById('history-tbody');

    if (!tbody) return;



    const searchInput = document.getElementById('history-search-input');

    const riskSelect = document.getElementById('history-filter-risk');

    const statusSelect = document.getElementById('history-filter-status');



    const search = (searchInput ? searchInput.value : '').toLowerCase().trim();

    const risk = (riskSelect ? riskSelect.value : '').toUpperCase();

    const stat = (statusSelect ? statusSelect.value : '').toUpperCase();



    const items = (state.historyList || []).filter(item => {

        const matchSearch = !search ||

            (item.filename && item.filename.toLowerCase().includes(search)) ||

            (item.sha256 && item.sha256.toLowerCase().includes(search)) ||

            (item.analysis_id && item.analysis_id.toLowerCase().includes(search));



        const matchRisk = !risk || (item.classification && item.classification.toUpperCase() === risk);

        const matchStatus = !stat || (item.status && item.status.toUpperCase() === stat);



        return matchSearch && matchRisk && matchStatus;

    });



    if (items.length === 0) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">No analysis records match your search filter.</td></tr>`;

        return;

    }



    tbody.innerHTML = items.map(item => {

        const shortHash = item.sha256 ? `${item.sha256.substring(0, 12)}...` : 'N/A';

        const dateStr = item.created_at ? item.created_at.replace('T', ' ').substring(0, 19) : 'N/A';

        const riskLevel = item.classification || 'LOW';

        const riskBadge = getRiskBadgeClass(riskLevel);

        const score = item.risk_score !== undefined ? item.risk_score : 0;



        return `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td class="font-mono"><strong>${escapeHtml(item.analysis_id)}</strong></td>

                <td>

                    <div style="font-weight: 600;">${escapeHtml(item.filename)}</div>

                    <div style="font-size: 11px; color: var(--text-muted);">${((item.size || 0) / 1024).toFixed(1)} KB</div>

                </td>

                <td><span class="badge badge-rule">${escapeHtml(item.file_type || 'EXE')} (${escapeHtml(item.architecture || 'x64')})</span></td>

                <td class="font-mono">

                    <span title="${escapeHtml(item.sha256)}">${shortHash}</span>

                    <button class="btn-icon-copy" data-action="copy-sha256" data-value="${escapeHtml(item.sha256)}" title="Copy full SHA-256">­ƒôï</button>

                </td>

                <td>

                    <span class="badge ${riskBadge}">${riskLevel} (${score}/100)</span>

                </td>

                <td style="font-size: 12px; color: var(--text-secondary);">${dateStr}</td>

                <td>

                    <div style="display: flex; gap: 6px; align-items: center;">

                        <button class="btn-primary" style="padding: 4px 8px; font-size: 11px;" data-action="open-analysis" title="Load into Workspace">­ƒôé Open</button>

                        <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" data-action="view-report" title="View Report">­ƒôä Report</button>

                    </div>

                </td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

}



async function openAnalysisInWorkspace(analysisId) {

    try {

        state.activeAnalysisId = analysisId;

        const response = await fetchWithAuth(`/api/analyses/${encodeURIComponent(analysisId)}?language=${state.currentLanguage}`);

        if (!response.ok) {

            throw new Error('Failed to fetch analysis details from database.');

        }



        const data = await response.json();

        state.sampleData = data;

        state.activeAnalysisId = data.analysis_id || analysisId;

        renderSampleData(data);

        switchTab('analysis');



    } catch (err) {

        alert(`Could not open analysis: ${err.message}`);

    }

}




function handleHistoryTableClick(event) {
    const row = event.target.closest('tr[data-analysis-id]');
    if (!row) return;

    const analysisId = row.dataset.analysisId;

    if (event.target.matches('[data-action="copy-sha256"]')) {
        const value = event.target.dataset.value;
        copyTextToClipboard(value);
        showSocNotification('Copied', 'SHA-256 copied to clipboard', 'success');
    } else if (event.target.matches('[data-action="open-analysis"]')) {
        openAnalysisInWorkspace(analysisId);
    } else if (event.target.matches('[data-action="view-report"]')) {
        const url = row.dataset.url;
        window.open(url, '_blank');
    }
}

function copyTextToClipboard(text) {

    if (!navigator.clipboard) {

        prompt('Copy text:', text);

        return;

    }

    navigator.clipboard.writeText(text).then(() => {

        // Feedback

    }).catch(() => {

        prompt('Copy text:', text);

    });

}



/**

 * ============================================================================

 * STRING INTELLIGENCE CONTROLLER (Module 06)

 * Real forensic extraction, categorization, search, filtering, and export

 * ============================================================================

 */

state.stringsData = null;

// ============================================================================

// MODULE: STRING FORENSIC INTELLIGENCE WORKSPACE

// ============================================================================



state.stringsData = null;

state.stringsList = [];

state.stringsFilteredList = [];

state.stringsCurrentPage = 1;

state.stringsPageSize = 50;

state.stringsTotalPages = 1;

state.stringsSelectedModalItem = null;

state.stringsModalAnalysesList = [];

state.stringsActiveQuickFilter = 'ALL';

state.stringsIsWrapEnabled = true;



function renderStatEl(elementId, value) {

    const el = document.getElementById(elementId);

    if (el) el.textContent = value;

}



/**

 * Load and Render String Intelligence

 * Priority:

 * 1. Explicit analysisId parameter

 * 2. URL query parameter '?analysis_id=...'

 * 3. Selected analysis from global application state

 * 4. Most recently completed analysis from database

 * 5. Otherwise show "No Analysis Selected"

 */

async function loadStringsIntelligence(analysisId = null, resetFilters = false) {

    const banner = document.getElementById('strings-no-analysis-banner');

    const content = document.getElementById('strings-content-container');

    const tbody = document.getElementById('strings-tbody');

    const aiSummaryEl = document.getElementById('strings-ai-summary-text');

    const aiStatusBadge = document.getElementById('strings-ai-status-badge');



    let targetId = analysisId;



    // 1. Check URL search param

    if (!targetId) {

        const urlParams = new URLSearchParams(window.location.search);

        targetId = urlParams.get('analysis_id');

    }



    // 2. Check global state

    if (!targetId) {

        targetId = state.activeAnalysisId || (state.sampleData ? (state.sampleData.analysis_id || state.sampleData.id) : null);

    }



    // 3. Check most recently completed analysis from server

    if (!targetId) {

        try {

            const historyRes = await fetchWithAuth('/api/analyses?limit=1');

            if (historyRes.ok) {

                const historyData = await historyRes.json();

                if (historyData.items && historyData.items.length > 0) {

                    targetId = historyData.items[0].analysis_id;

                }

            }

        } catch (e) {

            console.warn('Could not auto-fetch recent analysis:', e);

        }

    }



    // 4. If no analysis exists anywhere, show NO ANALYSIS SELECTED

    if (!targetId) {

        if (banner) banner.style.display = 'block';

        if (content) content.style.display = 'none';

        return;

    }



    // Analysis found: show content workspace

    if (banner) banner.style.display = 'none';

    if (content) content.style.display = 'block';



    state.activeAnalysisId = targetId;



    // Update URL query without page reload

    if (window.history && window.history.replaceState) {

        const newUrl = new URL(window.location);

        newUrl.searchParams.set('analysis_id', targetId);

        window.history.replaceState(null, '', newUrl.toString());

    }



    if (tbody) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="10" class="empty-state-cell" style="padding: 28px;">Extracting and classifying static strings for <code>${escapeHtml(targetId)}</code>...</td></tr>`;

    }

    if (aiSummaryEl) aiSummaryEl.textContent = '­ƒñû AI Security Analyst synthesizing forensic string intelligence...';

    if (aiStatusBadge) {

        aiStatusBadge.textContent = 'ANALYZING...';

        aiStatusBadge.className = 'badge badge-rule';

    }



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(targetId)}/strings?page_size=500`);

        if (!res.ok) {

            throw new Error(`Failed to retrieve string intelligence (HTTP ${res.status})`);

        }

        const data = await res.json();

        state.stringsData = data;

        state.stringsList = data.strings || [];



        // Update Topbar Sample Badge

        const sampleBadge = document.getElementById('current-sample-badge');

        const sampleName = document.getElementById('current-sample-name');

        if (sampleBadge && sampleName) {

            sampleBadge.style.display = 'flex';

            sampleName.textContent = data.filename || targetId;

        }



        // Render Ribbon & Header Information

        const filenameEl = document.getElementById('strings-active-filename');

        const idEl = document.getElementById('strings-active-analysis-id');

        const shaEl = document.getElementById('strings-active-sha256');

        const totalCounterEl = document.getElementById('strings-active-total-counter');

        const statusEl = document.getElementById('strings-active-status-badge');



        if (filenameEl) filenameEl.textContent = data.filename || 'sample.exe';

        if (idEl) idEl.textContent = data.analysis_id || targetId;

        if (shaEl) shaEl.textContent = data.sha256 || 'Not available';

        if (totalCounterEl) totalCounterEl.textContent = (data.total_strings || state.stringsList.length).toLocaleString();

        if (statusEl) {

            statusEl.textContent = data.status || 'COMPLETED';

            statusEl.className = data.status === 'COMPLETED' ? 'badge badge-low' : 'badge badge-high';

        }



        // Render 8 Summary Statistics Cards

        const stats = data.statistics || {};

        const totalStr = stats.total !== undefined ? stats.total : state.stringsList.length;

        const suspCount = stats.suspicious_count || 0;

        const urlsCount = stats.urls_count || 0;

        const domainsCount = stats.domains_count || 0;

        const ipsCount = stats.ips_count || 0;

        const regCount = stats.registry_count || 0;

        const cmdsCount = stats.commands_count || 0;

        const psCount = stats.powershell_count || 0;

        const asciiCount = stats.ascii_count || 0;

        const unicodeCount = stats.unicode_count || 0;

        const apisCount = stats.apis_count || 0;



        renderStatEl('stat-total-strings', totalStr.toLocaleString());

        renderStatEl('stat-total-sub', `${asciiCount.toLocaleString()} ASCII / ${unicodeCount.toLocaleString()} Unicode`);

        renderStatEl('stat-suspicious-strings', suspCount.toLocaleString());

        renderStatEl('stat-suspicious-sub', suspCount > 0 ? 'Forensic Indicators' : 'Clean Baseline');

        renderStatEl('stat-urls-domains', (urlsCount + domainsCount).toLocaleString());

        renderStatEl('stat-urls-sub', `${urlsCount} URLs / ${domainsCount} Domains`);

        renderStatEl('stat-ip-addresses', ipsCount.toLocaleString());

        renderStatEl('stat-ips-sub', 'IPv4 Endpoints');

        renderStatEl('stat-registry-paths', regCount.toLocaleString());

        renderStatEl('stat-registry-sub', 'Persistence & Config');

        renderStatEl('stat-commands-scripts', (cmdsCount + psCount).toLocaleString());

        renderStatEl('stat-commands-sub', `${psCount} PowerShell / ${cmdsCount} CLI`);

        renderStatEl('stat-ascii-strings', asciiCount.toLocaleString());

        renderStatEl('stat-unicode-strings', unicodeCount.toLocaleString());



        // Update Quick-Triage Pill Count Badges

        renderStatEl('pill-all-count', totalStr.toLocaleString());

        renderStatEl('pill-susp-count', suspCount.toLocaleString());

        renderStatEl('pill-net-count', (urlsCount + domainsCount).toLocaleString());

        renderStatEl('pill-ips-count', ipsCount.toLocaleString());

        renderStatEl('pill-reg-count', regCount.toLocaleString());

        renderStatEl('pill-cmd-count', (cmdsCount + psCount).toLocaleString());

        renderStatEl('pill-api-count', apisCount.toLocaleString());



        // Render AI Intelligence Summary

        if (aiSummaryEl) {

            aiSummaryEl.textContent = data.ai_string_summary || 'Static string classification complete. Findings scoped from in-memory byte analysis.';

        }

        if (aiStatusBadge) {

            if (suspCount > 0) {

                aiStatusBadge.textContent = `${suspCount} SUSPICIOUS CLUES`;

                aiStatusBadge.className = 'badge badge-high';

            } else {

                aiStatusBadge.textContent = 'CLEAN BASELINE';

                aiStatusBadge.className = 'badge badge-low';

            }

        }



        if (resetFilters) {

            clearStringsFilters(false);

        }



        applyStringsFilterAndRender();



    } catch (err) {

        if (tbody) {

            tbody.innerHTML = `

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td colspan="10" class="empty-state-cell" style="color: var(--sev-high); padding: 24px;">

                        <div style="font-weight: 700; margin-bottom: 6px;">STRING EXTRACTION FAILED</div>

                        <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">${escapeHtml(err.message)}</div>

                        <div style="display: flex; gap: 8px; justify-content: center;">

                            <button class="btn-secondary" onclick="reloadCurrentStrings()">Retry</button>

                            <button class="btn-primary" onclick="openStringsSelectAnalysisModal()">Choose Another Sample</button>

                        </div>

                    </td>

                </tr>

            `;

        }

        if (aiSummaryEl) aiSummaryEl.textContent = `String intelligence unavailable: ${err.message}`;

        if (aiStatusBadge) {

            aiStatusBadge.textContent = 'ERROR';

            aiStatusBadge.className = 'badge badge-crit';

        }

    }

}



/**

 * Contextual Cross-View Navigation preserving Analysis ID

 */

function navigateToAnalysisTab(targetTab) {

    if (state.activeAnalysisId) {

        const newUrl = new URL(window.location);

        newUrl.searchParams.set('analysis_id', state.activeAnalysisId);

        window.history.replaceState(null, '', newUrl.toString());

    }

    switchTab(targetTab);

}



/**

 * Select Analysis Modal Controls

 */

async function openStringsSelectAnalysisModal() {

    const modal = document.getElementById('strings-select-analysis-modal');

    if (modal) modal.style.display = 'flex';

    await loadAnalysesForStringsModal();

}



function closeStringsSelectAnalysisModal() {

    const modal = document.getElementById('strings-select-analysis-modal');

    if (modal) modal.style.display = 'none';

}



async function loadAnalysesForStringsModal() {

    const tbody = document.getElementById('strings-modal-analyses-tbody');

    if (tbody) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">Loading available analyses from database...</td></tr>`;

    }



    try {

        const res = await fetchWithAuth('/api/analyses?limit=50');

        if (!res.ok) throw new Error('Failed to fetch analysis records');

        const data = await res.json();

        state.stringsModalAnalysesList = data.items || [];

        renderStringsModalAnalysesList();

    } catch (err) {

        if (tbody) {

            tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell" style="color: var(--sev-high);">Failed to load analyses: ${escapeHtml(err.message)}</td></tr>`;

        }

    }

}



function filterStringsModalAnalyses() {

    renderStringsModalAnalysesList();

}



function renderStringsModalAnalysesList() {

    const tbody = document.getElementById('strings-modal-analyses-tbody');

    const searchIn = document.getElementById('strings-modal-search');

    if (!tbody) return;



    const term = (searchIn ? searchIn.value : '').toLowerCase().trim();

    const list = (state.stringsModalAnalysesList || []).filter(item => {

        if (!term) return true;

        return (

            (item.filename || '').toLowerCase().includes(term) ||

            (item.analysis_id || '').toLowerCase().includes(term) ||

            (item.sha256 || '').toLowerCase().includes(term)

        );

    });



    if (list.length === 0) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">No analyses matching criteria.</td></tr>`;

        return;

    }



    tbody.innerHTML = list.map(a => {

        const isCurrent = a.analysis_id === state.activeAnalysisId;

        const shaShort = a.sha256 ? `${a.sha256.substring(0, 12)}...` : 'N/A';

        const dateStr = a.created_at ? a.created_at.substring(0, 19).replace('T', ' ') : 'Recent';

        const riskLevel = a.risk_level || (a.risk_score >= 75 ? 'CRITICAL' : (a.risk_score >= 50 ? 'HIGH' : (a.risk_score >= 25 ? 'MEDIUM' : 'LOW')));

        const riskBadge = `<span class="badge ${getRiskBadgeClass(riskLevel)}">${riskLevel} (${a.risk_score || 0})</span>`;



        return `

            <tr style="${isCurrent ? 'background: rgba(0, 240, 255, 0.05);' : ''}">

                <td><strong>${escapeHtml(a.filename || 'sample.exe')}</strong></td>

                <td><code style="font-family: var(--font-mono); color: var(--accent-cyan);">${escapeHtml(a.analysis_id)}</code></td>

                <td><code style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);" title="${escapeHtml(a.sha256 || '')}">${escapeHtml(shaShort)}</code></td>

                <td>${riskBadge}</td>

                <td><span class="badge badge-low">${escapeHtml(a.status || 'COMPLETED')}</span></td>

                <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(dateStr)}</td>

                <td style="text-align: center;">

                    <button class="btn-${isCurrent ? 'secondary' : 'primary'}" onclick="selectAnalysisForStrings('${escapeJsString(a.analysis_id)}')" style="font-size: 11px; padding: 3px 10px;">

                        ${isCurrent ? 'Ô£ô Active' : 'Open'}

                    </button>

                </td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

}



function selectAnalysisForStrings(analysisId) {

    closeStringsSelectAnalysisModal();

    state.activeAnalysisId = analysisId;

    const newUrl = new URL(window.location);

    newUrl.searchParams.set('analysis_id', analysisId);

    window.history.replaceState(null, '', newUrl.toString());



    if (state.currentTab === 'pe-analysis') {

        loadPeStructureAnalysis(analysisId);

    } else if (state.currentTab === 'imports') {

        loadImportsIntelligence(analysisId, true);

    } else if (state.currentTab === 'indicators') {

        loadIndicatorsAndIocs(analysisId);

    } else if (state.currentTab === 'ai-analyst') {

        loadAiAnalystView(analysisId);

    } else if (state.currentTab === 'reports') {

        loadReportsView(analysisId);

    } else if (state.currentTab === 'analysis') {

        loadSpecificAnalysis(analysisId);

    } else {

        loadStringsIntelligence(analysisId, true);

    }

    showSocNotification('Analysis Selected', `Loaded analysis record ${analysisId}`, 'success');

}



/**

 * Quick Triage Filter Pills

 */

function applyStringQuickFilter(filterType) {

    state.stringsActiveQuickFilter = filterType;



    // Update pill buttons visual state

    document.querySelectorAll('.quick-string-pill').forEach(btn => {

        btn.classList.remove('active');

    });

    const activePill = document.getElementById(`pill-${filterType.toLowerCase()}`);

    if (activePill) activePill.classList.add('active');



    const catSelect = document.getElementById('strings-filter-category');

    const suspCheck = document.getElementById('strings-filter-suspicious');



    if (filterType === 'ALL') {

        if (catSelect) catSelect.value = 'ALL';

        if (suspCheck) suspCheck.checked = false;

    } else if (filterType === 'SUSPICIOUS') {

        if (catSelect) catSelect.value = 'ALL';

        if (suspCheck) suspCheck.checked = true;

    } else {

        if (catSelect) catSelect.value = filterType;

        if (suspCheck) suspCheck.checked = false;

    }



    onStringsFilterChange();

}



function clearStringsFilters(triggerRender = true) {

    const searchIn = document.getElementById('strings-search-input');

    const catSel = document.getElementById('strings-filter-category');

    const sevSel = document.getElementById('strings-filter-severity');

    const encSel = document.getElementById('strings-filter-encoding');

    const suspChk = document.getElementById('strings-filter-suspicious');

    const sortSel = document.getElementById('strings-sort-by');



    if (searchIn) searchIn.value = '';

    if (catSel) catSel.value = 'ALL';

    if (sevSel) sevSel.value = 'ALL';

    if (encSel) encSel.value = 'ALL';

    if (suspChk) suspChk.checked = false;

    if (sortSel) sortSel.value = 'severity';



    document.querySelectorAll('.quick-string-pill').forEach(btn => btn.classList.remove('active'));

    const allPill = document.getElementById('pill-all');

    if (allPill) allPill.classList.add('active');



    if (triggerRender) {

        onStringsFilterChange();

    }

}



function onStringsFilterChange() {

    state.stringsCurrentPage = 1;

    applyStringsFilterAndRender();

}



function onStringsPageSizeChange() {

    const sel = document.getElementById('strings-page-size-select');

    if (sel) {

        state.stringsPageSize = parseInt(sel.value, 10) || 50;

    }

    state.stringsCurrentPage = 1;

    applyStringsFilterAndRender();

}



function reloadCurrentStrings() {

    loadStringsIntelligence(state.activeAnalysisId, false);

}



function applyStringsFilterAndRender() {

    const searchInput = document.getElementById('strings-search-input');

    const catSelect = document.getElementById('strings-filter-category');

    const sevSelect = document.getElementById('strings-filter-severity');

    const encSelect = document.getElementById('strings-filter-encoding');

    const suspCheck = document.getElementById('strings-filter-suspicious');

    const sortSelect = document.getElementById('strings-sort-by');



    const search = (searchInput ? searchInput.value : '').toLowerCase().trim();

    const category = (catSelect ? catSelect.value : 'ALL').toUpperCase();

    const severity = (sevSelect ? sevSelect.value : 'ALL').toUpperCase();

    const encoding = (encSelect ? encSelect.value : 'ALL').toUpperCase();

    const suspiciousOnly = suspCheck ? suspCheck.checked : false;

    const sortBy = sortSelect ? sortSelect.value : 'severity';



    // 1. Filter

    const filtered = (state.stringsList || []).filter(s => {

        // Search filter

        if (search) {

            const valMatch = (s.value || '').toLowerCase().includes(search);

            const catMatch = (s.category || '').toLowerCase().includes(search);

            const reasonMatch = (s.reason || '').toLowerCase().includes(search);

            const mitreMatch = (s.mitre_technique || '').toLowerCase().includes(search);

            const offMatch = (s.offset_hex || '').toLowerCase().includes(search);

            if (!valMatch && !catMatch && !reasonMatch && !mitreMatch && !offMatch) return false;

        }



        // Category filter

        if (category !== 'ALL') {

            const sCat = (s.category || '').toUpperCase();

            if (category === 'COMMAND' && !['COMMAND', 'CMD', 'POWERSHELL', 'SCRIPT'].includes(sCat)) return false;

            if (category === 'URL' && !['URL', 'DOMAIN'].includes(sCat)) return false;

            if (category === 'IP_ADDRESS' && sCat !== 'IP_ADDRESS' && sCat !== 'IP') return false;

            if (category === 'REGISTRY' && sCat !== 'REGISTRY' && sCat !== 'REGISTRY_PATH') return false;

            if (!['COMMAND', 'URL', 'IP_ADDRESS', 'REGISTRY'].includes(category) && sCat !== category) return false;

        }



        // Severity filter

        if (severity !== 'ALL') {

            if ((s.severity || 'INFO').toUpperCase() !== severity) return false;

        }



        // Encoding filter

        if (encoding !== 'ALL') {

            if ((s.encoding || 'ASCII').toUpperCase() !== encoding) return false;

        }



        // Suspicious only

        if (suspiciousOnly && !s.suspicious) {

            return false;

        }



        return true;

    });



    // 2. Sort

    const sevOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4 };

    filtered.sort((a, b) => {

        if (sortBy === 'offset_asc') {

            return (a.offset || 0) - (b.offset || 0);

        } else if (sortBy === 'offset_desc') {

            return (b.offset || 0) - (a.offset || 0);

        } else if (sortBy === 'category') {

            return (a.category || '').localeCompare(b.category || '');

        } else if (sortBy === 'value') {

            return (a.value || '').localeCompare(b.value || '');

        } else if (sortBy === 'length_desc') {

            return (b.value ? b.value.length : 0) - (a.value ? a.value.length : 0);

        } else if (sortBy === 'length_asc') {

            return (a.value ? a.value.length : 0) - (b.value ? b.value.length : 0);

        } else {

            // Default: severity/suspicious first, then offset

            const diff = (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5);

            if (diff !== 0) return diff;

            return (a.offset || 0) - (b.offset || 0);

        }

    });



    state.stringsFilteredList = filtered;

    state.stringsTotalPages = Math.max(1, Math.ceil(filtered.length / state.stringsPageSize));

    if (state.stringsCurrentPage > state.stringsTotalPages) {

        state.stringsCurrentPage = state.stringsTotalPages;

    }



    renderStringsTableSlice();

}



function renderStringsTableSlice() {

    const tbody = document.getElementById('strings-tbody');

    const summaryEl = document.getElementById('strings-pagination-summary');

    const matchCountEl = document.getElementById('strings-filter-match-count');

    if (!tbody) return;



    const list = state.stringsFilteredList || [];

    const total = list.length;

    const totalOverall = (state.stringsList || []).length;



    if (total === 0) {

        tbody.innerHTML = `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td colspan="10" class="empty-state-cell" style="padding: 32px; text-align: center;">

                    <div style="font-size: 14px; font-weight: 700; margin-bottom: 6px;">NO STRINGS MATCHING FILTERS</div>

                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">Try clearing search or adjusting category / severity filters.</div>

                    <button class="btn-secondary" onclick="clearStringsFilters()">Clear Filters</button>

                </td>

            </tr>

        `;

        if (summaryEl) summaryEl.textContent = `Showing 0-0 of 0 strings`;

        if (matchCountEl) matchCountEl.textContent = `Showing 0 strings (${totalOverall.toLocaleString()} total)`;

        renderStringsPaginationControls(0, 0, 0);

        return;

    }



    const startIdx = (state.stringsCurrentPage - 1) * state.stringsPageSize;

    const endIdx = Math.min(startIdx + state.stringsPageSize, total);

    const slice = list.slice(startIdx, endIdx);



    if (summaryEl) summaryEl.textContent = `Showing ${(startIdx + 1).toLocaleString()}-${endIdx.toLocaleString()} of ${total.toLocaleString()} strings`;

    if (matchCountEl) matchCountEl.textContent = `Showing ${total.toLocaleString()} filtered strings (${totalOverall.toLocaleString()} total)`;



    tbody.innerHTML = slice.map((item, index) => {

        const globalIdx = startIdx + index;

        const offsetStr = item.offset_hex || (item.offset !== null && item.offset !== undefined ? `0x${item.offset.toString(16).toUpperCase().padStart(8, '0')}` : '0x00000000');

        const sevClass = getRiskBadgeClass(item.severity || 'LOW');

        const isSusp = item.suspicious;

        const catBadge = getCategoryBadgeHtml(item.category || 'GENERAL');

        const strLen = item.value ? item.value.length : 0;

        const confPct = Math.round((item.confidence || 1.0) * 100);



        // Truncate long display value gracefully

        const displayVal = item.value.length > 65 ? item.value.substring(0, 65) + '...' : item.value;



        return `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td style="text-align: center; color: var(--text-muted); font-size: 11px;">${globalIdx + 1}</td>

                <td><span class="badge ${sevClass}" style="font-size: 10px;">${escapeHtml(item.severity || 'INFO')}</span></td>

                <td>

                    <div style="display: flex; align-items: center; gap: 6px;">

                        <code style="font-family: var(--font-mono); font-size: 12px; color: ${isSusp ? 'var(--accent-orange)' : 'var(--text-primary)'}; word-break: break-all; cursor: pointer;" title="${escapeHtml(item.value)}">${escapeHtml(displayVal)}</code>

                    </div>

                </td>

                <td>${catBadge}</td>

                <td><span class="badge badge-rule" style="font-size: 10px;">${escapeHtml(item.encoding || 'ASCII')}</span></td>

                <td><code style="font-family: var(--font-mono); font-size: 11px; color: var(--accent-cyan);">${escapeHtml(offsetStr)}</code></td>

                <td style="font-size: 11px; color: var(--text-muted);">${strLen}B</td>

                <td style="font-size: 11px; font-weight: 600; color: var(--text-secondary);">${confPct}%</td>

                <td style="font-size: 11px; color: var(--text-secondary); max-width: 220px;">

                    <div style="line-height: 1.3;">${escapeHtml(item.reason || 'Standard string')}</div>

                    ${item.mitre_technique ? `<div style="font-size: 9px; color: var(--accent-cyan); margin-top: 2px;">­ƒÄ» ${escapeHtml(item.mitre_technique)}</div>` : ''}

                </td>

                <td style="text-align: center;">

                    <div style="display: flex; gap: 4px; justify-content: center; align-items: center;">

                        <button class="btn-secondary" data-action="copy-string" data-global-idx="${globalIdx}" style="font-size: 10px; padding: 2px 6px;" title="Copy string text">­ƒôï</button>

                        <button class="btn-primary" data-action="inspect-string" data-global-idx="${globalIdx}" style="font-size: 10px; padding: 2px 7px;" title="Inspect forensic details">­ƒöì</button>

                    </div>

                </td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);



    renderStringsPaginationControls(state.stringsCurrentPage, state.stringsTotalPages, total);

}



function getCategoryBadgeHtml(cat) {

    const c = (cat || 'GENERAL').toUpperCase();

    if (c === 'POWERSHELL') return `<span class="badge badge-high" style="font-size: 10px;">PowerShell</span>`;

    if (c === 'CMD') return `<span class="badge badge-mod" style="font-size: 10px;">CMD</span>`;

    if (c === 'COMMAND') return `<span class="badge badge-mod" style="font-size: 10px;">Command</span>`;

    if (c === 'URL') return `<span class="badge badge-rule" style="font-size: 10px; border-color: #38bdf8; color: #38bdf8;">URL</span>`;

    if (c === 'DOMAIN') return `<span class="badge badge-rule" style="font-size: 10px; border-color: #38bdf8; color: #38bdf8;">Domain</span>`;

    if (c === 'IP_ADDRESS' || c === 'IP') return `<span class="badge badge-rule" style="font-size: 10px; border-color: #fb923c; color: #fb923c;">IP</span>`;

    if (c === 'REGISTRY' || c === 'REGISTRY_PATH') return `<span class="badge badge-rule" style="font-size: 10px; border-color: #a855f7; color: #a855f7;">Registry</span>`;

    if (c === 'API') return `<span class="badge badge-rule" style="font-size: 10px; border-color: #ec4899; color: #ec4899;">API</span>`;

    if (c === 'DLL') return `<span class="badge badge-rule" style="font-size: 10px;">DLL</span>`;

    if (c === 'FILE_PATH') return `<span class="badge badge-rule" style="font-size: 10px;">File Path</span>`;

    if (c === 'EMAIL') return `<span class="badge badge-rule" style="font-size: 10px;">Email</span>`;

    if (c === 'SCRIPT') return `<span class="badge badge-mod" style="font-size: 10px;">Script</span>`;

    if (c === 'SUSPICIOUS') return `<span class="badge badge-crit" style="font-size: 10px;">Suspicious</span>`;

    return `<span class="badge badge-low" style="font-size: 10px;">General</span>`;

}



function renderStringsPaginationControls(currentPage, totalPages, totalItems) {

    const btnFirst = document.getElementById('btn-strings-first');

    const btnPrev = document.getElementById('btn-strings-prev');

    const btnNext = document.getElementById('btn-strings-next');

    const btnLast = document.getElementById('btn-strings-last');

    const numbersContainer = document.getElementById('strings-page-numbers');



    if (btnFirst) btnFirst.disabled = currentPage <= 1;

    if (btnPrev) btnPrev.disabled = currentPage <= 1;

    if (btnNext) btnNext.disabled = currentPage >= totalPages;

    if (btnLast) btnLast.disabled = currentPage >= totalPages;



    if (!numbersContainer) return;



    if (totalPages <= 1) {

        numbersContainer.innerHTML = '';

        return;

    }



    const pages = [];

    const maxButtons = 5;

    let startPage = Math.max(1, currentPage - 2);

    let endPage = Math.min(totalPages, startPage + maxButtons - 1);

    if (endPage - startPage < maxButtons - 1) {

        startPage = Math.max(1, endPage - maxButtons + 1);

    }



    for (let p = startPage; p <= endPage; p++) {

        pages.push(p);

    }



    numbersContainer.innerHTML = pages.map(p => `

        <button class="btn-secondary ${p === currentPage ? 'active' : ''}" data-action="goto-page" data-page="${p}" style="font-size: 11px; padding: 4px 8px; ${p === currentPage ? 'background: var(--accent-cyan); color: #0b1324; font-weight: bold;' : ''}">

            ${p}

        </button>

    `).join('');

}




function handleStringsTableClick(event) {
    const row = event.target.closest('tr[data-global-idx]');
    if (!row) return;

    const globalIdx = parseInt(row.dataset.globalIdx, 10);

    if (event.target.matches('[data-action="copy-string"]')) {
        copySingleString(globalIdx, event.target);
    } else if (event.target.matches('[data-action="inspect-string"]')) {
        openStringDetailModal(globalIdx);
    }
}


function handleStringsPaginationClick(event) {
    const btn = event.target.closest('[data-action="goto-page"]');
    if (!btn) return;
    const page = parseInt(btn.dataset.page, 10);
    if (!isNaN(page)) {
        goToStringsPage(page);
    }
}

function goToStringsPage(pageNum) {

    const target = Math.max(1, Math.min(pageNum, state.stringsTotalPages || 1));

    state.stringsCurrentPage = target;

    renderStringsTableSlice();

}



/**

 * String Forensic Detail Drawer & Interactive AI

 */

function openStringDetailModal(index) {

    const item = (state.stringsFilteredList || [])[index];

    if (!item) return;



    state.stringsSelectedModalItem = item;



    const modal = document.getElementById('string-detail-modal');

    const valEl = document.getElementById('modal-string-value');

    const catEl = document.getElementById('modal-string-category');

    const encEl = document.getElementById('modal-string-encoding');

    const offEl = document.getElementById('modal-string-offset');

    const sevEl = document.getElementById('modal-string-severity');

    const reasonEl = document.getElementById('modal-string-reason');

    const mitreBox = document.getElementById('modal-string-mitre-box');

    const mitreNameEl = document.getElementById('modal-string-mitre-name');

    const sampleNameEl = document.getElementById('modal-string-sample-name');

    const sampleShaEl = document.getElementById('modal-string-sample-sha');

    const aiAnswerBox = document.getElementById('modal-string-ai-answer');

    const aiInput = document.getElementById('modal-ask-ai-input');



    if (valEl) {

        valEl.textContent = item.value;

        valEl.style.whiteSpace = 'pre-wrap';

    }

    if (catEl) catEl.innerHTML = getCategoryBadgeHtml(item.category);

    if (encEl) encEl.textContent = `${item.encoding || 'ASCII'} (${item.value.length} bytes)`;

    if (offEl) offEl.textContent = item.offset_hex || `0x${(item.offset || 0).toString(16).toUpperCase()}`;

    if (sevEl) {

        const sevBadge = `<span class="badge ${getRiskBadgeClass(item.severity)}">${item.severity || 'INFO'}</span>`;

        const confText = `<span style="color: var(--text-muted); font-size: 11px; margin-left: 6px;">${Math.round((item.confidence || 1.0) * 100)}% Confidence</span>`;

        sevEl.innerHTML = `${sevBadge} ${confText}`;

    }

    if (reasonEl) reasonEl.textContent = item.reason || 'Standard printable text or metadata artifact.';



    if (item.mitre_technique) {

        if (mitreBox) mitreBox.style.display = 'block';

        if (mitreNameEl) mitreNameEl.textContent = item.mitre_technique;

    } else {

        if (mitreBox) mitreBox.style.display = 'none';

    }



    if (sampleNameEl) sampleNameEl.textContent = (state.stringsData && state.stringsData.filename) || (state.sampleData ? state.sampleData.filename : 'sample.exe');

    if (sampleShaEl) sampleShaEl.textContent = (state.stringsData && state.stringsData.sha256) || (state.sampleData ? state.sampleData.sha256 : 'N/A');



    if (aiAnswerBox) aiAnswerBox.style.display = 'none';

    if (aiInput) aiInput.value = '';



    if (modal) modal.style.display = 'flex';

}



function closeStringDetailModal() {

    const modal = document.getElementById('string-detail-modal');

    if (modal) modal.style.display = 'none';

}



function toggleModalStringWrap() {

    const valEl = document.getElementById('modal-string-value');

    const btn = document.getElementById('btn-modal-wrap-toggle');

    if (!valEl) return;

    state.stringsIsWrapEnabled = !state.stringsIsWrapEnabled;

    valEl.style.whiteSpace = state.stringsIsWrapEnabled ? 'pre-wrap' : 'pre';

    if (btn) btn.textContent = state.stringsIsWrapEnabled ? 'Unwrap' : 'Wrap Text';

}



function copyModalStringValue() {

    if (!state.stringsSelectedModalItem) return;

    const text = state.stringsSelectedModalItem.value;

    const btn = document.getElementById('btn-modal-copy-string');

    copyTextToClipboardWithFeedback(text, btn, '­ƒôï Copy String');

}



function copyModalStringOffset() {

    if (!state.stringsSelectedModalItem) return;

    const offsetStr = state.stringsSelectedModalItem.offset_hex || `0x${(state.stringsSelectedModalItem.offset || 0).toString(16).toUpperCase()}`;

    navigator.clipboard.writeText(offsetStr);

    showSocNotification('Copied Offset', `Offset ${offsetStr} copied to clipboard`, 'success');

}



function searchSimilarStringsFromModal() {

    if (!state.stringsSelectedModalItem) return;

    const item = state.stringsSelectedModalItem;

    closeStringDetailModal();

    const searchIn = document.getElementById('strings-search-input');

    if (searchIn) {

        searchIn.value = item.category !== 'GENERAL' ? item.category : item.value.substring(0, 16);

        onStringsFilterChange();

    }

}



function askAiModalPrompt(promptText) {

    const input = document.getElementById('modal-ask-ai-input');

    if (input) {

        input.value = promptText;

        executeModalAskAi();

    }

}



async function executeModalAskAi() {

    const input = document.getElementById('modal-ask-ai-input');

    const answerBox = document.getElementById('modal-string-ai-answer');

    const btn = document.getElementById('btn-modal-ask-ai');

    if (!input || !answerBox || !state.stringsSelectedModalItem) return;



    const question = input.value.trim() || 'What does this string indicate in malware analysis?';

    const item = state.stringsSelectedModalItem;

    const analysisId = state.activeAnalysisId || (state.stringsData ? state.stringsData.analysis_id : '');



    answerBox.style.display = 'block';

    answerBox.innerHTML = '<span style="color: var(--accent-cyan);">­ƒñû AI Security Analyst investigating string context...</span>';

    if (btn) btn.disabled = true;



    try {

        const fullPrompt = `Regarding extracted string "${item.value}" (Category: ${item.category}, Encoding: ${item.encoding}, Offset: ${item.offset_hex}): ${question}`;

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(analysisId)}/ask-ai`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ question: fullPrompt, language: state.currentLanguage || 'en' })

        });

        if (!res.ok) throw new Error('AI analysis service unavailable');

        const data = await res.json();

        answerBox.innerHTML = `

            <div style="font-weight: 700; color: var(--accent-cyan); margin-bottom: 4px;">­ƒñû AI Forensic Scoping:</div>

            <div>${escapeHtml(data.answer)}</div>

            <div style="font-size: 10px; color: var(--text-muted); margin-top: 6px;"><em>Static indicator analysis. String presence alone does not establish confirmed runtime malicious execution.</em></div>

        `;

    } catch (err) {

        answerBox.innerHTML = `<span style="color: var(--sev-high);">AI Query Error: ${escapeHtml(err.message)}</span>`;

    } finally {

        if (btn) btn.disabled = false;

    }

}



function copySingleString(index, btnElement) {

    const item = (state.stringsFilteredList || [])[index];

    if (!item) return;

    copyTextToClipboardWithFeedback(item.value, btnElement, '­ƒôï');

}



function copyActiveAnalysisId() {

    const id = state.activeAnalysisId;

    if (id) {

        navigator.clipboard.writeText(id);

        showSocNotification('Copied ID', `Analysis ID ${id} copied to clipboard`, 'success');

    }

}



function copyActiveSha256() {

    const sha = state.stringsData ? state.stringsData.sha256 : (state.sampleData ? state.sampleData.sha256 : '');

    const btn = document.getElementById('strings-copy-sha256-btn');

    if (sha) {

        copyTextToClipboardWithFeedback(sha, btn, '­ƒôï');

    }

}



function copyTextToClipboardWithFeedback(text, btnElement, defaultLabel) {

    if (!text) return;

    if (navigator.clipboard && navigator.clipboard.writeText) {

        navigator.clipboard.writeText(text).then(() => {

            if (btnElement) {

                btnElement.textContent = 'Ô£ô Copied!';

                btnElement.style.color = '#10b981';

                setTimeout(() => {

                    btnElement.textContent = defaultLabel;

                    btnElement.style.color = '';

                }, 1500);

            }

            showSocNotification('Copied', 'Text copied to clipboard.', 'success');

        }).catch(() => {

            prompt('Copy string:', text);

        });

    } else {

        prompt('Copy string:', text);

    }

}



/**

 * Real String Evidence Exports (CSV, JSON, TXT)

 */

function exportStringsCSV() {

    const list = state.stringsFilteredList && state.stringsFilteredList.length > 0 ? state.stringsFilteredList : state.stringsList;

    if (!list || list.length === 0) {

        alert('No strings available to export.');

        return;

    }



    const headers = ['Index', 'String Value', 'Category', 'Encoding', 'Offset Hex', 'Offset Dec', 'Suspicious', 'Severity', 'Confidence', 'Reason', 'MITRE ATT&CK'];

    const rows = list.map((s, idx) => [

        idx + 1,

        `"${(s.value || '').replace(/"/g, '""')}"`,

        s.category || 'GENERAL',

        s.encoding || 'ASCII',

        s.offset_hex || `0x${(s.offset || 0).toString(16).toUpperCase()}`,

        s.offset || 0,

        s.suspicious ? 'YES' : 'NO',

        s.severity || 'INFO',

        s.confidence || 1.0,

        `"${(s.reason || '').replace(/"/g, '""')}"`,

        `"${(s.mitre_technique || '').replace(/"/g, '""')}"`

    ]);



    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });

    const filename = `strings_${state.activeAnalysisId || 'export'}.csv`;

    downloadBlobFile(blob, filename);

    showSocNotification('Export Complete', `Exported ${list.length} strings as CSV`, 'success');

}



function exportStringsJSON() {

    const data = state.stringsData || {

        analysis_id: state.activeAnalysisId || 'ANL-UNKNOWN',

        filename: state.sampleData ? state.sampleData.filename : 'sample.exe',

        total_strings: state.stringsList.length,

        strings: state.stringsList

    };



    const jsonStr = JSON.stringify(data, null, 2);

    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8;' });

    const filename = `strings_${state.activeAnalysisId || 'export'}.json`;

    downloadBlobFile(blob, filename);

    showSocNotification('Export Complete', `Exported ${state.stringsList.length} strings as JSON`, 'success');

}



function exportStringsTXT() {

    const list = state.stringsFilteredList && state.stringsFilteredList.length > 0 ? state.stringsFilteredList : state.stringsList;

    if (!list || list.length === 0) {

        alert('No strings available to export.');

        return;

    }



    const id = state.activeAnalysisId || 'ANL-UNKNOWN';

    const fn = (state.stringsData && state.stringsData.filename) || (state.sampleData ? state.sampleData.filename : 'sample.exe');

    const sha = (state.stringsData && state.stringsData.sha256) || 'N/A';



    let txt = `===============================================================================\n`;

    txt += `  ETHIO-AI DEFENDER - STATIC STRING FORENSIC INVESTIGATION REPORT\n`;

    txt += `===============================================================================\n`;

    txt += `Analysis ID: ${id}\n`;

    txt += `Filename:    ${fn}\n`;

    txt += `SHA-256:     ${sha}\n`;

    txt += `Total Count: ${list.length} extracted strings\n`;

    txt += `Generated:   ${new Date().toISOString()}\n`;

    txt += `-------------------------------------------------------------------------------\n\n`;



    list.forEach((s, idx) => {

        txt += `[#${idx + 1}] [${s.severity || 'INFO'}] [${s.category || 'GENERAL'}] [${s.encoding || 'ASCII'}] Offset: ${s.offset_hex || '0x0000'}\n`;

        txt += `String: ${s.value}\n`;

        if (s.reason) txt += `Reason: ${s.reason}\n`;

        if (s.mitre_technique) txt += `MITRE:  ${s.mitre_technique}\n`;

        txt += `\n`;

    });



    const blob = new Blob([txt], { type: 'text/plain;charset=utf-8;' });

    const filename = `strings_summary_${id}.txt`;

    downloadBlobFile(blob, filename);

    showSocNotification('Export Complete', `Exported string summary as TXT`, 'success');

}



function downloadBlobFile(blob, filename) {

    const link = document.createElement('a');

    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);

    link.setAttribute('download', filename);

    link.style.visibility = 'hidden';

    document.body.appendChild(link);

    link.click();

    document.body.removeChild(link);

    URL.revokeObjectURL(url);

}



function renderBulletList(containerId, list) {

    const container = document.getElementById(containerId);

    if (!container) return;

    if (list && list.length > 0) {

        container.innerHTML = list.map(item => `<li>${escapeHtml(item)}</li>`).join('');

    } else {

        container.innerHTML = `<li>None available.</li>`;

    }

}



/**

 * Filter Imports Table

 */

function filterImportsTable() {

    const query = (document.getElementById('imports-search-input').value || '').toLowerCase();

    const rows = document.querySelectorAll('#imports-tbody tr');

    rows.forEach(row => {

        const text = row.textContent.toLowerCase();

        row.style.display = text.includes(query) ? '' : 'none';

    });

}



/**

 * Cybersecurity Student Learning Lab Controller (Module 12 & 16)

 */

state.studentCurrentSubtab = 'overview';

state.labActiveResultTab = 'headers';

state.practiceSamplesList = [];

state.quizQuestionsList = [];



function switchStudentTab(subtab = 'overview') {

    state.studentCurrentSubtab = subtab;

    const tabs = ['overview', 'concepts', 'labs', 'quizzes', 'anatomy'];



    tabs.forEach(t => {

        const btn = document.getElementById(`student-subtab-${t}`);

        const panel = document.getElementById(`student-panel-${t}`);

        if (btn) btn.classList.toggle('active', t === subtab);

        if (panel) panel.style.display = (t === subtab) ? 'block' : 'none';

    });



    if (subtab === 'overview') {

        loadStudentDashboardStats();

    } else if (subtab === 'concepts') {

        renderSelectedConcept();

    } else if (subtab === 'labs') {

        loadPracticeSamples();

    } else if (subtab === 'quizzes') {

        loadQuizQuestions();

    }

}



async function loadStudentDashboardStats() {

    try {

        const res = await fetchWithAuth('/api/learning/dashboard-stats');

        if (!res || !res.ok) return;

        const data = await res.json();



        // 1. Animate 4 Hero KPI Cards

        animateCounter('student-overview-labs-completed', data.labs_completed || 2);

        animateCounter('student-overview-analyses-completed', data.personal_analyses_count || 0);



        const courseEl = document.getElementById('student-overview-course');

        if (courseEl) courseEl.textContent = data.current_course || 'PE Analysis';



        const skillLvlEl = document.getElementById('student-overview-skill-level');

        if (skillLvlEl) skillLvlEl.textContent = data.skill_level || 'APPRENTICE';



        // 2. Animate Dynamic Skill Matrix

        const skills = data.skill_matrix || {

            pe_analysis: 75,

            static_strings: 80,

            iat_apis: 60,

            entropy_detection: 45,

            ioc_scoring: 65

        };



        const updateSkill = (valId, barId, pct) => {

            const v = document.getElementById(valId);

            const b = document.getElementById(barId);

            if (v) v.textContent = `${pct}%`;

            if (b) b.style.width = `${pct}%`;

        };



        updateSkill('skill-pe-val', 'skill-pe-bar', skills.pe_analysis || 75);

        updateSkill('skill-strings-val', 'skill-strings-bar', skills.static_strings || 80);

        updateSkill('skill-iat-val', 'skill-iat-bar', skills.iat_apis || 60);

        updateSkill('skill-entropy-val', 'skill-entropy-bar', skills.entropy_detection || 45);

        updateSkill('skill-iocs-val', 'skill-iocs-bar', skills.ioc_scoring || 65);



        // 3. Update Learning Path Pipeline

        updateAnalysisPipeline(data.current_stage || 4, 'student-pipeline-stages');

    } catch (err) {

        console.warn('Error loading student dashboard stats:', err);

    }

}



function setLearningDifficulty(diff) {

    state.currentDifficulty = diff;

    const btnBeg = document.getElementById('diff-beginner');

    const btnAdv = document.getElementById('diff-advanced');

    if (btnBeg) btnBeg.classList.toggle('active', diff === 'BEGINNER');

    if (btnAdv) btnAdv.classList.toggle('active', diff === 'ADVANCED');

    renderSelectedConcept();

}



async function renderSelectedConcept() {

    const select = document.getElementById('learning-topic-select');

    const topicKey = select ? select.value : 'PE_FORMAT';

    const lang = state.currentLanguage || 'en';

    const diff = state.currentDifficulty || 'BEGINNER';



    try {

        const res = await fetchWithAuth(`/api/learning/topics/${topicKey}?lang=${lang}&level=${diff}`);

        if (res && res.ok) {

            const data = await res.json();

            document.getElementById('lesson-title').textContent = data.title;

            document.getElementById('lesson-what-is-it').textContent = data.what_is_it;

            document.getElementById('lesson-why-matters').textContent = data.why_it_matters;

            

            const badgeEl = document.getElementById('lesson-level-badge');

            if (badgeEl) {

                badgeEl.textContent = diff === 'BEGINNER' ? 'Beginner Level' : 'Advanced Level';

                badgeEl.className = diff === 'BEGINNER' ? 'badge badge-low' : 'badge badge-high';

            }

            document.getElementById('lesson-explanation-body').textContent = data.explanation;

            document.getElementById('lesson-proves-malicious').textContent = data.proves_malicious;

            renderBulletList('lesson-next-steps', data.what_to_learn_next || []);



            // Render Visual Anatomy table if available

            const anatomySection = document.getElementById('lesson-anatomy-section');

            const anatomySummary = document.getElementById('lesson-anatomy-summary');

            const anatomyTbody = document.getElementById('lesson-anatomy-tbody');



            if (data.visual_anatomy && data.visual_anatomy.fields && data.visual_anatomy.fields.length > 0) {

                if (anatomySection) anatomySection.style.display = 'block';

                if (anatomySummary) anatomySummary.textContent = `${data.visual_anatomy.structure_name} ÔÇö ${data.visual_anatomy.summary}`;

                if (anatomyTbody) {

                    anatomyTbody.innerHTML = data.visual_anatomy.fields.map(f => `

                        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                            <td><code>${escapeHtml(f.offset)}</code></td>

                            <td style="color: var(--text-muted);">${escapeHtml(f.size)}</td>

                            <td style="font-weight: 600; color: var(--accent-blue);"><code>${escapeHtml(f.field_name)}</code></td>

                            <td>${escapeHtml(f.description)}</td>

                            <td><code style="color: #10b981;">${escapeHtml(f.sample_value)}</code></td>

                        </tr>

                    `).join('');

                }

            } else {

                if (anatomySection) anatomySection.style.display = 'none';

            }

            return;

        }

    } catch (e) {

        console.warn('Could not fetch topic from learning API, falling back to static database:', e);

    }



    // Fallback to local CONCEPTS_DB

    const concept = (CONCEPTS_DB[topicKey] && CONCEPTS_DB[topicKey][lang]) ? CONCEPTS_DB[topicKey][lang] : (CONCEPTS_DB[topicKey]?.en || CONCEPTS_DB.WINDOWS_APIS.en);

    if (concept) {

        document.getElementById('lesson-title').textContent = concept.title;

        document.getElementById('lesson-what-is-it').textContent = concept.what_is_it;

        document.getElementById('lesson-why-matters').textContent = concept.why_it_matters;

        document.getElementById('lesson-level-badge').textContent = diff === 'BEGINNER' ? 'Beginner Level' : 'Advanced Level';

        document.getElementById('lesson-explanation-body').textContent = diff === 'BEGINNER' ? concept.beginner : concept.advanced;

        document.getElementById('lesson-proves-malicious').textContent = concept.proves;

        renderBulletList('lesson-next-steps', concept.next);

        const anatomySection = document.getElementById('lesson-anatomy-section');

        if (anatomySection) anatomySection.style.display = 'none';

    }

}



/**

 * Safe Educational Practice Labs

 */

async function loadPracticeSamples() {

    const grid = document.getElementById('student-practice-cards-grid');

    if (!grid) return;



    try {

        const res = await fetchWithAuth('/api/learning/practice-samples');

        if (!res || !res.ok) {

            grid.innerHTML = '<div class="empty-state-cell">Unable to load practice lab catalog.</div>';

            return;

        }

        state.practiceSamplesList = await res.json();



        grid.innerHTML = state.practiceSamplesList.map(s => {

            const diffClass = s.difficulty === 'BEGINNER' ? 'badge-low' : (s.difficulty === 'INTERMEDIATE' ? 'badge-mod' : 'badge-high');

            const learningBullets = (s.key_learning_points || []).map(p => `<li style="font-size: 11px; margin-bottom: 4px;">Ô£ô ${escapeHtml(p)}</li>`).join('');

            const expectedPills = (s.expected_findings || []).map(f => `<span class="badge badge-low" style="font-size: 10px; margin: 2px;">­ƒÄ» ${escapeHtml(f)}</span>`).join('');



            return `

                <div class="soc-card" style="display: flex; flex-direction: column; justify-content: space-between; border-top: 3px solid var(--accent-blue);">

                    <div>

                        <div class="card-head flex-between" style="padding-bottom: 8px;">

                            <span class="badge ${diffClass}" style="font-size: 10px; font-weight: 700;">${escapeHtml(s.difficulty)}</span>

                            <span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(s.file_type)}</span>

                        </div>

                        <h4 style="font-size: 14px; font-weight: 700; color: var(--text-primary); margin: 6px 0 8px 0;">${escapeHtml(s.title)}</h4>

                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 12px;">${escapeHtml(s.description)}</p>

                        

                        <div style="background: rgba(255,255,255,0.02); border-radius: 4px; padding: 8px 12px; margin-bottom: 12px;">

                            <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Learning Focus:</div>

                            <ul style="list-style: none; padding: 0; margin: 0; color: var(--text-secondary);">

                                ${learningBullets}

                            </ul>

                        </div>



                        <div style="margin-bottom: 14px;">

                            <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Expected Triage Findings:</div>

                            <div style="display: flex; flex-wrap: wrap;">

                                ${expectedPills}

                            </div>

                        </div>

                    </div>



                    <div style="padding-top: 12px; border-top: 1px solid var(--border-color);">

                        <button id="btn-load-sample-${s.id}" class="btn-primary" onclick="loadPracticeSampleInLab('${s.id}')" style="width: 100%; font-size: 12px; padding: 8px 12px; display: flex; align-items: center; justify-content: center; gap: 6px;">

                            ­ƒö¼ Load & Analyze Sample in Lab

                        </button>

                    </div>

                </div>

            `;

        }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

    } catch (err) {

        grid.innerHTML = `<div class="empty-state-cell">Error: ${escapeHtml(err.message)}</div>`;

    }

}



async function loadPracticeSampleInLab(sampleId) {

    const btn = document.getElementById(`btn-load-sample-${sampleId}`);

    const originalText = btn ? btn.innerHTML : '';

    if (btn) {

        btn.disabled = true;

        btn.innerHTML = 'ÔÜÖ´©Å Analyzing Safe Binary...';

    }



    try {

        const lang = state.currentLanguage || 'en';

        const res = await fetchWithAuth(`/api/learning/practice-samples/${sampleId}/load?lang=${lang}`, {

            method: 'POST'

        });



        if (!res || !res.ok) {

            const data = await res.json();

            alert('Failed to load practice sample: ' + (data.detail || res.statusText));

            return;

        }



        const data = await res.json();

        state.sampleData = data.analysis_data;



        // Render active lab inspection container

        const labContainer = document.getElementById('student-active-lab-result');

        const labTitle = document.getElementById('lab-active-title');

        const summaryBox = document.getElementById('lab-analysis-summary-box');

        const metricsGrid = document.getElementById('lab-analysis-metrics-grid');



        if (labContainer) labContainer.style.display = 'block';

        if (labTitle) labTitle.textContent = `­ƒö¼ Active Practice Lab: ${data.sample_meta.title}`;



        const sample = data.analysis_data;

        const riskLevel = sample.risk_level || sample.classification || 'BENIGN';

        const riskScore = sample.risk_score !== undefined ? sample.risk_score : 0;

        const sha256 = sample.sha256 || sample.hashes?.sha256 || '-';



        if (summaryBox) {

            summaryBox.innerHTML = `

                <div style="background: rgba(14, 165, 233, 0.08); border: 1px solid rgba(14, 165, 233, 0.3); border-radius: 6px; padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">

                    <div>

                        <div style="font-size: 14px; font-weight: 700; color: var(--text-primary); margin-bottom: 2px;">

                            ${escapeHtml(sample.filename || data.sample_meta.filename)}

                            <span class="badge badge-low" style="margin-left: 8px; font-size: 10px;">­ƒøí´©Å ZERO-EXECUTION SAFE</span>

                        </div>

                        <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">

                            SHA-256: ${escapeHtml(sha256)}

                        </div>

                    </div>

                    <div style="display: flex; align-items: center; gap: 10px;">

                        <span class="badge ${getRiskBadgeClass(riskLevel)}" style="font-size: 12px; font-weight: 700; padding: 4px 10px;">

                            ${escapeHtml(riskLevel)} (${riskScore}/100)

                        </span>

                    </div>

                </div>

            `;

        }



        if (metricsGrid) {

            const entropyVal = sample.entropy?.full_file_entropy || sample.entropy_overall || 0;

            const sectionsCount = sample.pe_headers?.number_of_sections || sample.sections?.length || 0;

            const importsCount = sample.imports?.total_imports || sample.imports?.functions_count || 0;

            const stringsCount = sample.strings?.total_extracted || sample.strings?.length || 0;



            metricsGrid.innerHTML = `

                <div class="soc-metric-card">

                    <span class="metric-label">Shannon Entropy</span>

                    <span class="metric-val" style="color: ${entropyVal > 7.2 ? 'var(--sev-high)' : 'var(--accent-blue)'};">${Number(entropyVal).toFixed(3)}</span>

                    <span class="metric-sub">${entropyVal > 7.2 ? 'ÔÜá´©Å High Randomness / Dense' : 'Ô£ô Uncompressed / Normal'}</span>

                </div>

                <div class="soc-metric-card">

                    <span class="metric-label">Memory Sections</span>

                    <span class="metric-val">${sectionsCount}</span>

                    <span class="metric-sub">Mapped in Headers</span>

                </div>

                <div class="soc-metric-card">

                    <span class="metric-label">Imported APIs</span>

                    <span class="metric-val">${importsCount}</span>

                    <span class="metric-sub">External OS Dependencies</span>

                </div>

                <div class="soc-metric-card">

                    <span class="metric-label">Extracted Strings</span>

                    <span class="metric-val">${stringsCount}</span>

                    <span class="metric-sub">Printable Clues</span>

                </div>

            `;

        }



        // Render subpanels inside active lab

        renderLabHeaders(sample);

        renderLabSections(sample);

        renderLabImports(sample);

        renderLabStrings(sample);



        // Scroll to active lab result

        if (labContainer) labContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });



    } catch (err) {

        alert('Error analyzing practice sample: ' + err.message);

    } finally {

        if (btn) {

            btn.disabled = false;

            btn.innerHTML = originalText;

        }

    }

}



function switchLabResultTab(subtab) {

    state.labActiveResultTab = subtab;

    const tabs = ['headers', 'sections', 'imports', 'strings'];

    tabs.forEach(t => {

        const btn = document.getElementById(`lab-view-${t}`);

        const panel = document.getElementById(`lab-panel-${t}`);

        if (btn) btn.classList.toggle('active', t === subtab);

        if (panel) panel.style.display = (t === subtab) ? 'block' : 'none';

    });

}



function renderLabHeaders(sample) {

    const tbody = document.getElementById('lab-headers-tbody');

    if (!tbody) return;

    const pe = sample.pe_headers || {};

    tbody.innerHTML = `

        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td style="font-weight: 600; width: 220px;">Target Architecture</td><td><code>${escapeHtml(pe.machine_architecture || pe.machine || 'x86 (32-bit)')}</code></td></tr>

        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td style="font-weight: 600;">Subsystem</td><td><code>${escapeHtml(pe.subsystem || 'Windows GUI / Console')}</code></td></tr>

        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td style="font-weight: 600;">Address of Entry Point (EP)</td><td><code>${escapeHtml(pe.entry_point_rva || pe.entry_point || '0x00001000')}</code></td></tr>

        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td style="font-weight: 600;">Preferred Image Base</td><td><code>${escapeHtml(pe.image_base || '0x00400000')}</code></td></tr>

        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td style="font-weight: 600;">Compile Timestamp</td><td><code>${escapeHtml(pe.compile_time || pe.timestamp_iso || '2026-01-01')}</code></td></tr>

        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td style="font-weight: 600;">Security Mitigations</td><td><code>ASLR: ${pe.aslr_enabled ? 'Ô£ô Enabled' : 'Ô£ò Disabled'} | DEP: ${pe.dep_enabled ? 'Ô£ô Enabled' : 'Ô£ò Disabled'}</code></td></tr>

    `;

}



function renderLabSections(sample) {

    const tbody = document.getElementById('lab-sections-tbody');

    if (!tbody) return;

    const sections = sample.sections || (sample.pe_headers && sample.pe_headers.sections) || [];

    if (sections.length === 0) {

        tbody.innerHTML = '<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="6" class="empty-state-cell">No sections found in sample.</td></tr>';

        return;

    }

    tbody.innerHTML = sections.map(s => {

        const ent = s.entropy !== undefined ? Number(s.entropy).toFixed(2) : '-';

        const isHigh = s.entropy && s.entropy > 7.2;

        const wxViolation = s.characteristics_flags && (s.characteristics_flags.includes('WRITE') && s.characteristics_flags.includes('EXECUTE'));

        

        return `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td style="font-weight: 600; color: var(--accent-blue);"><code>${escapeHtml(s.name)}</code></td>

                <td>${formatBytes(s.virtual_size || 0)}</td>

                <td>${formatBytes(s.raw_size || s.size_of_raw_data || 0)}</td>

                <td style="font-weight: 700; color: ${isHigh ? '#f87171' : 'var(--text-primary)'};">${ent}</td>

                <td><span style="font-size: 11px; color: ${wxViolation ? '#f87171' : 'var(--text-muted)'};">${escapeHtml(s.permissions || s.characteristics_flags?.join(', ') || 'R-E')}</span></td>

                <td>${wxViolation ? '<span class="badge badge-crit">ÔÜá´©Å W+X Permission</span>' : (isHigh ? '<span class="badge badge-high">ÔÜá´©Å High Entropy</span>' : '<span class="badge badge-low">Normal</span>')}</td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

}



function renderLabImports(sample) {

    const container = document.getElementById('lab-imports-container');

    if (!container) return;

    const imports = sample.imports?.libraries || sample.imports?.dll_imports || sample.imports || [];

    if (!Array.isArray(imports) || imports.length === 0) {

        container.innerHTML = '<div class="empty-state-cell">No external imports found in this sample.</div>';

        return;

    }

    container.innerHTML = `

        <div style="display: flex; flex-direction: column; gap: 10px;">

            ${imports.slice(0, 5).map(lib => `

                <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px;">

                    <div style="font-weight: 700; color: var(--accent-blue); font-size: 13px; margin-bottom: 6px;">­ƒôª ${escapeHtml(lib.dll_name || lib.name || 'Library')}</div>

                    <div style="display: flex; flex-wrap: wrap; gap: 6px;">

                        ${(lib.functions || lib.imported_functions || []).map(fn => `

                            <code style="font-size: 11px; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">${escapeHtml(typeof fn === 'string' ? fn : (fn.name || 'API'))}</code>

                        `).join('')}

                    </div>

                </div>

            `).join('')}

        </div>

    `;

}



function renderLabStrings(sample) {

    const container = document.getElementById('lab-strings-container');

    if (!container) return;

    const strings = sample.strings?.all_strings || sample.strings || [];

    if (!Array.isArray(strings) || strings.length === 0) {

        container.innerHTML = '<div class="empty-state-cell">No strings extracted.</div>';

        return;

    }

    const sampleStrings = strings.slice(0, 30);

    container.innerHTML = `

        <div style="background: var(--bg-darkest, #0b1120); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; max-height: 240px; overflow-y: auto; font-family: var(--font-mono); font-size: 11px; line-height: 1.6;">

            ${sampleStrings.map(s => `<div>${escapeHtml(typeof s === 'string' ? s : (s.value || s.string || ''))}</div>`).join('')}

        </div>

    `;

}



function viewLabInFullAnalysis() {

    if (state.sampleData) {

        switchTab('analysis');

    }

}



function closeActivePracticeLab() {

    const labContainer = document.getElementById('student-active-lab-result');

    if (labContainer) labContainer.style.display = 'none';

}



/**

 * Interactive Knowledge Quizzes

 */

async function loadQuizQuestions(reset = false) {

    const container = document.getElementById('quiz-questions-container');

    const badge = document.getElementById('quiz-status-badge');

    const scoreCard = document.getElementById('quiz-result-score-card');

    if (!container) return;



    if (reset && scoreCard) scoreCard.style.display = 'none';

    if (badge) {

        badge.textContent = 'Ready';

        badge.className = 'badge badge-low';

    }



    try {

        const res = await fetchWithAuth('/api/learning/quizzes');

        if (!res || !res.ok) {

            container.innerHTML = '<div class="empty-state-cell">Unable to load quiz questions.</div>';

            return;

        }

        state.quizQuestionsList = await res.json();



        container.innerHTML = state.quizQuestionsList.map((q, idx) => `

            <div id="quiz-q-card-${q.id}" class="soc-card" style="padding: 16px; border-left: 3px solid var(--accent-blue);">

                <div class="flex-between" style="margin-bottom: 8px;">

                    <span style="font-size: 11px; font-weight: 700; color: var(--accent-blue); text-transform: uppercase;">Question ${idx + 1} (${escapeHtml(q.topic)})</span>

                    <span class="badge badge-low" style="font-size: 10px;">${escapeHtml(q.difficulty)}</span>

                </div>

                <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 12px;">${escapeHtml(q.question)}</div>



                <div style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 10px;">

                    ${q.options.map(opt => `

                        <label style="display: flex; align-items: flex-start; gap: 10px; font-size: 12px; color: var(--text-secondary); cursor: pointer; padding: 6px 10px; border-radius: 4px; background: rgba(255,255,255,0.02); border: 1px solid transparent;" id="quiz-opt-label-${q.id}-${opt.id}">

                            <input type="radio" name="quiz-q-${q.id}" value="${opt.id}" style="margin-top: 2px;" required>

                            <span><strong>${opt.id.toUpperCase()})</strong> ${escapeHtml(opt.text)}</span>

                        </label>

                    `).join('')}

                </div>



                <div style="display: flex; justify-content: space-between; align-items: center;">

                    <button type="button" class="btn-secondary" onclick="toggleQuizHint('${q.id}')" style="font-size: 10px; padding: 2px 8px;">­ƒÆí Hint</button>

                    <div id="quiz-q-result-${q.id}" style="font-size: 11px; font-weight: 700;"></div>

                </div>

                <div id="quiz-hint-${q.id}" style="display: none; font-size: 11px; color: var(--text-muted); margin-top: 8px; padding: 6px 10px; background: rgba(255,255,255,0.02); border-radius: 4px;">

                    <em>Hint: ${escapeHtml(q.hint)}</em>

                </div>

                <div id="quiz-explanation-${q.id}" style="display: none; font-size: 12px; color: var(--text-primary); margin-top: 8px; padding: 8px 12px; background: rgba(16,185,129,0.08); border-left: 3px solid #10b981; border-radius: 4px;"></div>

            </div>

        `).join('');

    } catch (err) {

        container.innerHTML = `<div class="empty-state-cell">Error: ${escapeHtml(err.message)}</div>`;

    }

}



function toggleQuizHint(qId) {

    const hintEl = document.getElementById(`quiz-hint-${qId}`);

    if (hintEl) {

        hintEl.style.display = (hintEl.style.display === 'none' || !hintEl.style.display) ? 'block' : 'none';

    }

}



async function handleQuizSubmit(event) {

    event.preventDefault();

    if (!state.quizQuestionsList || state.quizQuestionsList.length === 0) return;



    const answers = [];

    for (const q of state.quizQuestionsList) {

        const selected = document.querySelector(`input[name="quiz-q-${q.id}"]:checked`);

        if (!selected) {

            alert(`Please answer Question ${q.id.replace('q', '')} before submitting.`);

            return;

        }

        answers.push({

            question_id: q.id,

            selected_option_id: selected.value

        });

    }



    try {

        const res = await fetchWithAuth('/api/learning/quizzes/evaluate', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ answers })

        });



        if (!res || !res.ok) {

            alert('Failed to grade quiz.');

            return;

        }



        const data = await res.json();

        const scoreCard = document.getElementById('quiz-result-score-card');

        const badge = document.getElementById('quiz-status-badge');

        const heading = document.getElementById('quiz-result-heading');

        const pct = document.getElementById('quiz-result-percentage');

        const msg = document.getElementById('quiz-result-message');



        if (scoreCard) scoreCard.style.display = 'block';

        if (badge) {

            badge.textContent = data.passed ? 'PASSED' : 'RETRY';

            badge.className = data.passed ? 'badge badge-low' : 'badge badge-high';

        }

        if (heading) heading.textContent = data.passed ? '­ƒÄô Mastery Assessment: PASSED' : '­ƒôÜ Mastery Assessment: Review Needed';

        if (pct) {

            pct.textContent = `${data.score_percentage}% (${data.correct_count}/${data.total_questions})`;

            pct.style.color = data.passed ? '#10b981' : '#f87171';

        }

        if (msg) {

            msg.textContent = data.passed

                ? 'Excellent work! You demonstrated strong comprehension of Windows PE structures, entropy analysis, and defensive static triage principles.'

                : 'Good effort! Review the detailed rationales below for any incorrect answers, inspect the Visual PE Architecture diagram, and retry the quiz.';

        }



        // Render per-question results

        data.results.forEach(r => {

            const resultEl = document.getElementById(`quiz-q-result-${r.question_id}`);

            const expEl = document.getElementById(`quiz-explanation-${r.question_id}`);

            const cardEl = document.getElementById(`quiz-q-card-${r.question_id}`);



            if (resultEl) {

                resultEl.textContent = r.is_correct ? 'Ô£ô Correct' : 'Ô£ò Incorrect';

                resultEl.style.color = r.is_correct ? '#10b981' : '#f87171';

            }

            if (expEl) {

                expEl.style.display = 'block';

                expEl.innerHTML = `<strong>Technical Rationale:</strong> ${escapeHtml(r.explanation)}`;

                expEl.style.borderLeftColor = r.is_correct ? '#10b981' : '#f87171';

                expEl.style.background = r.is_correct ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)';

            }

            if (cardEl) {

                cardEl.style.borderLeftColor = r.is_correct ? '#10b981' : '#f87171';

            }

        });



        if (scoreCard) scoreCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });



    } catch (err) {

        alert('Error evaluating quiz: ' + err.message);

    }

}



/**

 * Helpers

 */

function getRiskBadgeClass(level) {

    const l = (level || '').toUpperCase();

    if (l === 'CRITICAL') return 'badge-crit';

    if (l === 'HIGH') return 'badge-high';

    if (l === 'SUSPICIOUS') return 'badge-susp';

    if (l === 'MODERATE') return 'badge-mod';

    return 'badge-low';

}



function getScoreColor(level) {

    const l = (level || '').toUpperCase();

    if (l === 'CRITICAL') return 'var(--sev-crit)';

    if (l === 'HIGH') return 'var(--sev-high)';

    if (l === 'SUSPICIOUS') return 'var(--sev-susp)';

    if (l === 'MODERATE') return 'var(--sev-mod)';

    return 'var(--sev-low)';

}



function escapeHtml(str) {

    if (!str) return '';

    return String(str)

        .replace(/&/g, '&amp;')

        .replace(/</g, '&lt;')

        .replace(/>/g, '&gt;')

        .replace(/"/g, '&quot;')

        .replace(/'/g, '&#039;');

}



/**

 * SEC-07: Escape an untrusted value for safe inclusion inside a JavaScript

 * string literal that is itself embedded in an inline HTML event-handler

 * attribute (e.g. onclick="fn('VALUE')").

 *

 * escapeHtml() is NOT sufficient here: the HTML parser decodes entities such

 * as &#039; back into a raw quote BEFORE the JavaScript engine parses the

 * handler, which allows attribute-to-script breakout. This helper emits only

 * backslash-escaped \xHH sequences, so neither the HTML attribute nor the JS

 * string literal can be terminated by attacker-controlled text.

 */

function escapeJsString(str) {

    if (str === undefined || str === null) return '';

    return String(str)

        .replace(/\\/g, '\\\\')

        .replace(/'/g, '\\x27')

        .replace(/"/g, '\\x22')

        .replace(/&/g, '\\x26')

        .replace(/</g, '\\x3c')

        .replace(/>/g, '\\x3e')

        .replace(/\r/g, '\\x0d')

        .replace(/\n/g, '\\x0a')

        .replace(/\t/g, '\\x09');

}



/**

 * Authentication and Access Control Management (Module 16)

 */

function setAuthLoading(isLoading, text = "Authenticating Security Workspace...") {

    const overlay = document.getElementById('auth-loading-overlay');

    if (!overlay) return;

    if (isLoading) {

        overlay.style.display = 'flex';

        overlay.style.opacity = '1';

        const textEl = overlay.querySelector('.auth-loading-text');

        if (textEl) textEl.textContent = text;

    } else {

        overlay.style.opacity = '0';

        setTimeout(() => {

            overlay.style.display = 'none';

        }, 150);

    }

}



function showConnectionError(msg) {

    const banner = document.getElementById('auth-connection-banner');

    if (banner) {

        banner.innerHTML = `<span>ÔÜá´©Å ${escapeHtml(msg)}</span> <button type="button" onclick="initAuth()" style="margin-left: 8px; background: none; border: 1px solid currentColor; color: inherit; border-radius: 4px; padding: 2px 8px; cursor: pointer; font-size: 11px;">­ƒöä Retry</button>`;

        banner.style.display = 'block';

    }

}



function clearConnectionError() {

    const banner = document.getElementById('auth-connection-banner');

    if (banner) {

        banner.style.display = 'none';

        banner.innerHTML = '';

    }

}



function renderLayoutForAuth() {

    const publicLayout = document.getElementById('public-layout');

    const appLayout = document.getElementById('app-layout');



    if (state.authStatus === 'AUTHENTICATED' && state.user) {

        if (publicLayout) publicLayout.style.display = 'none';

        if (appLayout) appLayout.style.display = 'flex';

    } else {

        if (appLayout) appLayout.style.display = 'none';

        if (publicLayout) publicLayout.style.display = 'flex';

    }

}



function renderNavigationForRole() {

    const navHome = document.getElementById('nav-item-home');

    const navHistory = document.getElementById('nav-item-history');

    const navAnalysis = document.getElementById('nav-item-analysis');

    const navPE = document.getElementById('nav-item-pe');

    const navImports = document.getElementById('nav-item-imports');

    const navStrings = document.getElementById('nav-item-strings');

    const navIndicators = document.getElementById('nav-item-indicators');

    const navAI = document.getElementById('nav-item-ai');

    const navReports = document.getElementById('nav-item-reports');

    const navLearning = document.getElementById('nav-item-learning');

    const navAdmin = document.getElementById('nav-item-admin');



    // Hide all navigation elements initially

    [navHome, navHistory, navAnalysis, navPE, navImports, navStrings, navIndicators, navAI, navReports, navLearning, navAdmin].forEach(el => {

        if (el) el.style.display = 'none';

    });



    if (!state.user || state.authStatus !== 'AUTHENTICATED') {

        return;

    }



    const role = (state.user.role || '').toUpperCase();

    const isAm = state.currentLanguage === 'am';



    if (role === 'ADMIN') {

        // ADMIN sees full SOC suite

        if (navAdmin) {

            navAdmin.style.display = 'block';

            const label = document.getElementById('nav-label-admin');

            if (label) label.textContent = isAm ? 'ßï¿ßèáßêÁßë░ßï│ßï│ßê¬ ßêøßïòßè¿ßêì' : 'Admin & Users';

        }

        if (navHome) {

            navHome.style.display = 'block';

            const label = document.getElementById('nav-label-home');

            if (label) label.textContent = isAm ? 'ßèáßï▓ßêÁ ßëÁßèòßë░ßèô' : 'Dashboard / Intake';

        }

        if (navHistory) {

            navHistory.style.display = 'block';

            const label = document.getElementById('nav-label-history');

            if (label) label.textContent = isAm ? 'ßï¿ßëÁßèòßë░ßèô ßë│ßê¬ßè¡' : 'Analysis History';

        }

        if (navAnalysis) {

            navAnalysis.style.display = 'block';

            const label = document.getElementById('nav-label-analysis');

            if (label) label.textContent = isAm ? 'ßëÁßèòßë░ßèô ßèÑßï¡ßë│' : 'Analysis Overview';

        }

        if (navPE) navPE.style.display = 'block';

        if (navImports) navImports.style.display = 'block';

        if (navStrings) navStrings.style.display = 'block';

        if (navIndicators) {

            navIndicators.style.display = 'block';

            const label = document.getElementById('nav-label-indicators');

            if (label) label.textContent = isAm ? 'ßï¿ßêÁßîïßëÁ ßêÿßê¿ßîâßïÄßë¢' : 'Threat Intelligence';

        }

        if (navAI) {

            navAI.style.display = 'block';

            const label = document.getElementById('nav-label-ai');

            if (label) label.textContent = isAm ? 'ßèáßï¡ßèáßï¡ ßë░ßèòßë│ßèØ' : 'AI Security Analyst';

        }

        if (navReports) {

            navReports.style.display = 'block';

            const label = document.getElementById('nav-label-reports');

            if (label) label.textContent = isAm ? 'ßï¿ßï░ßêàßèòßèÉßëÁ ßê¬ßìûßê¡ßëÂßë¢' : 'Security Reports';

        }

        if (navLearning) {

            navLearning.style.display = 'block';

            const label = document.getElementById('nav-label-learning');

            if (label) label.textContent = isAm ? 'ßï¿ßê│ßï¡ßëáßê¡ ßï░ßêàßèòßèÉßëÁ ßëÁßêØßêàßê¡ßëÁ' : 'Learning Center';

        }

    } else if (role === 'ANALYST') {

        // ANALYST sees complete malware analysis suite

        if (navHome) {

            navHome.style.display = 'block';

            const label = document.getElementById('nav-label-home');

            if (label) label.textContent = isAm ? 'ßèáßï▓ßêÁ ßëÁßèòßë░ßèô' : 'Dashboard / Intake';

        }

        if (navHistory) {

            navHistory.style.display = 'block';

            const label = document.getElementById('nav-label-history');

            if (label) label.textContent = isAm ? 'ßï¿ßëÁßèòßë░ßèô ßë│ßê¬ßè¡' : 'Analysis History';

        }

        if (navAnalysis) {

            navAnalysis.style.display = 'block';

            const label = document.getElementById('nav-label-analysis');

            if (label) label.textContent = isAm ? 'ßëÁßèòßë░ßèô ßèÑßï¡ßë│' : 'Analysis Overview';

        }

        if (navPE) navPE.style.display = 'block';

        if (navImports) navImports.style.display = 'block';

        if (navStrings) navStrings.style.display = 'block';

        if (navIndicators) {

            navIndicators.style.display = 'block';

            const label = document.getElementById('nav-label-indicators');

            if (label) label.textContent = isAm ? 'ßï¿ßêÁßîïßëÁ ßêÿßê¿ßîâßïÄßë¢' : 'Threat Intelligence';

        }

        if (navAI) {

            navAI.style.display = 'block';

            const label = document.getElementById('nav-label-ai');

            if (label) label.textContent = isAm ? 'ßèáßï¡ßèáßï¡ ßë░ßèòßë│ßèØ' : 'AI Security Analyst';

        }

        if (navReports) {

            navReports.style.display = 'block';

            const label = document.getElementById('nav-label-reports');

            if (label) label.textContent = isAm ? 'ßï¿ßï░ßêàßèòßèÉßëÁ ßê¬ßìûßê¡ßëÂßë¢' : 'Security Reports';

        }

        if (navLearning) {

            navLearning.style.display = 'block';

            const label = document.getElementById('nav-label-learning');

            if (label) label.textContent = isAm ? 'ßï¿ßê│ßï¡ßëáßê¡ ßï░ßêàßèòßèÉßëÁ ßëÁßêØßêàßê¡ßëÁ' : 'Learning Center';

        }

    } else if (role === 'STUDENT') {

        // STUDENT sees: Learning Center, Analysis Overview, PE, Imports, Strings,

        // Indicators, AI Analyst, Reports, History.

        // SEC-05 / P1: the generic binary upload intake ("Home") is intentionally

        // NOT shown ÔÇö Student accounts lack the UPLOAD_FILES permission and must

        // use the Safe Practice Labs instead.

        if (navLearning) {

            navLearning.style.display = 'block';

            const label = document.getElementById('nav-label-learning');

            if (label) label.textContent = isAm ? 'ßï¿ßë░ßêøßê¬ßïÄßë¢ ßêÿßêøßê¬ßï½' : 'Learning Center';

        }

        if (navAnalysis) {

            navAnalysis.style.display = 'block';

            const label = document.getElementById('nav-label-analysis');

            if (label) label.textContent = isAm ? 'ßëÁßèòßë░ßèô ßèÑßï¡ßë│' : 'Analysis Overview';

        }

        if (navPE) navPE.style.display = 'block';

        if (navImports) navImports.style.display = 'block';

        if (navStrings) navStrings.style.display = 'block';

        if (navIndicators) navIndicators.style.display = 'block';

        if (navAI) navAI.style.display = 'block';

        if (navReports) {

            navReports.style.display = 'block';

            const label = document.getElementById('nav-label-reports');

            if (label) label.textContent = isAm ? 'ßï¿ßï░ßêàßèòßèÉßëÁ ßê¬ßìûßê¡ßëÂßë¢' : 'Security Reports';

        }

        if (navHistory) {

            navHistory.style.display = 'block';

            const label = document.getElementById('nav-label-history');

            if (label) label.textContent = isAm ? 'ßï¿ßëÁßèòßë░ßèô ßë│ßê¬ßè¡' : 'Analysis History';

        }

    }

}



async function initAuth() {

    if (state.token) {

        state.authStatus = 'AUTHENTICATION_LOADING';

        setAuthLoading(true, "Authenticating Security Workspace...");

    } else {

        state.authStatus = 'UNAUTHENTICATED';

        state.user = null;

    }



    // Watchdog safety timeout (max 4s) to guarantee the spinner never remains stuck

    const watchdogTimer = setTimeout(() => {

        if (state.authStatus === 'AUTHENTICATION_LOADING') {

            console.warn("Auth initialization watchdog timeout reached. Forcing public login.");

            state.authStatus = 'UNAUTHENTICATED';

            state.user = null;

            renderLayoutForAuth();

            renderUserAuthWidget();

            renderNavigationForRole();

            setAuthLoading(false);

            handleUrlRouting();

            showConnectionError("Security server response timed out. Click Retry or sign in.");

        }

    }, 4000);



    try {

        if (state.token) {

            await fetchUserProfile();

        } else {

            state.user = null;

            state.authStatus = 'UNAUTHENTICATED';

            clearConnectionError();

        }



        renderLayoutForAuth();

        renderUserAuthWidget();

        renderNavigationForRole();

        handleUrlRouting();

    } catch (err) {

        console.warn("Authentication initialization error:", err);

        state.user = null;

        state.authStatus = 'UNAUTHENTICATED';

        renderLayoutForAuth();

        renderUserAuthWidget();

        renderNavigationForRole();

        handleUrlRouting();

        showConnectionError("Unable to connect to the security server. Please ensure the backend is running.");

    } finally {

        clearTimeout(watchdogTimer);

        setAuthLoading(false);

    }

}



function getAuthHeaders(headers = {}) {

    const h = { ...headers };

    if (state.token) {

        h['Authorization'] = `Bearer ${state.token}`;

    }

    return h;

}



async function fetchWithAuth(url, options = {}, timeoutMs = 3500) {

    const controller = new AbortController();

    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);



    options.headers = getAuthHeaders(options.headers || {});

    options.signal = controller.signal;



    try {

        const res = await fetch(url, options);

        clearTimeout(timeoutId);

        if (res.status === 401 && state.token) {

            // Token expired or revoked

            state.user = null;

            state.token = null;

            state.authStatus = 'UNAUTHENTICATED';

            localStorage.removeItem('ethio_auth_token');

        }

        return res;

    } catch (err) {

        clearTimeout(timeoutId);

        throw err;

    }

}



function switchAuthTab(tab) {

    const tabLogin = document.getElementById('modal-tab-login');

    const tabReg = document.getElementById('modal-tab-register');

    const formLogin = document.getElementById('auth-login-form');

    const formReg = document.getElementById('auth-register-form');



    if (tab === 'login') {

        if (tabLogin) tabLogin.classList.add('active');

        if (tabReg) tabReg.classList.remove('active');

        if (formLogin) formLogin.style.display = 'block';

        if (formReg) formReg.style.display = 'none';

    } else {

        if (tabLogin) tabLogin.classList.remove('active');

        if (tabReg) tabReg.classList.add('active');

        if (formLogin) formLogin.style.display = 'none';

        if (formReg) formReg.style.display = 'block';

    }

}



async function handleLoginForm(event) {

    event.preventDefault();

    const errBox = document.getElementById('login-error-box');

    const username = document.getElementById('login-username').value.trim();

    const password = document.getElementById('login-password').value;



    if (errBox) errBox.style.display = 'none';

    clearConnectionError();



    try {

        const res = await fetch('/api/auth/login', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ username, password })

        });

        const data = await res.json();



        if (!res.ok) {

            const msg = data.detail || 'Authentication failed.';

            if (errBox) {

                errBox.textContent = msg;

                errBox.style.display = 'block';

            }

            return;

        }



        state.token = data.access_token;

        localStorage.setItem('ethio_auth_token', state.token);

        await fetchUserProfile();

        renderLayoutForAuth();

        renderUserAuthWidget();

        renderNavigationForRole();

        routeUserByRole(true);

    } catch (err) {

        if (errBox) {

            errBox.textContent = 'Server connection error: ' + err.message;

            errBox.style.display = 'block';

        }

    }

}



async function handleRegisterForm(event) {

    event.preventDefault();

    const errBox = document.getElementById('register-error-box');

    const username = document.getElementById('reg-username').value.trim();

    const email = document.getElementById('reg-email').value.trim();

    const password = document.getElementById('reg-password').value;



    if (errBox) errBox.style.display = 'none';

    clearConnectionError();



    try {

        const res = await fetch('/api/auth/register', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ username, email, password })

        });

        const data = await res.json();



        if (!res.ok) {

            const msg = data.detail || 'Registration failed.';

            if (errBox) {

                errBox.textContent = msg;

                errBox.style.display = 'block';

            }

            return;

        }



        // Auto login after registration

        const loginRes = await fetch('/api/auth/login', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ username, password })

        });

        const loginData = await loginRes.json();

        if (loginRes.ok) {

            state.token = loginData.access_token;

            localStorage.setItem('ethio_auth_token', state.token);

            await fetchUserProfile();

            renderLayoutForAuth();

            renderUserAuthWidget();

            renderNavigationForRole();

            routeUserByRole(true);

        } else {

            switchAuthTab('login');

            const loginErr = document.getElementById('login-error-box');

            if (loginErr) {

                loginErr.textContent = 'Account created. Please sign in.';

                loginErr.style.display = 'block';

            }

        }

    } catch (err) {

        if (errBox) {

            errBox.textContent = 'Server connection error: ' + err.message;

            errBox.style.display = 'block';

        }

    }

}



async function fetchUserProfile() {

    if (!state.token) {

        state.user = null;

        state.authStatus = 'UNAUTHENTICATED';

        return;

    }



    try {

        const res = await fetchWithAuth('/api/auth/me', {}, 3500);

        if (res && res.ok) {

            state.user = await res.json();

            state.authStatus = 'AUTHENTICATED';

            clearConnectionError();

        } else if (res && (res.status === 401 || res.status === 403)) {

            state.user = null;

            state.token = null;

            state.authStatus = 'UNAUTHENTICATED';

            localStorage.removeItem('ethio_auth_token');

        } else {

            state.user = null;

            state.token = null;

            state.authStatus = 'UNAUTHENTICATED';

            localStorage.removeItem('ethio_auth_token');

            showConnectionError("Unable to verify security profile with the server.");

        }

    } catch (e) {

        console.warn('Could not fetch user profile:', e);

        state.user = null;

        state.authStatus = 'UNAUTHENTICATED';

        if (e.name === 'AbortError') {

            showConnectionError("Connection to security server timed out. Click Retry or sign in.");

        } else {

            showConnectionError("Unable to connect to the security server. Please ensure the backend is running.");

        }

    }

}



function updateUrlPath(newPath) {

    if (window.location.pathname !== newPath) {

        window.history.pushState({ path: newPath }, '', newPath);

    }

}



function showUnauthorizedView(message = null) {

    state.currentTab = 'unauthorized';

    document.querySelectorAll('.nav-link').forEach(btn => btn.classList.remove('active'));

    document.querySelectorAll('.view-panel').forEach(panel => {

        panel.classList.toggle('active', panel.id === 'view-unauthorized');

    });

    const msgEl = document.getElementById('unauthorized-message');

    if (msgEl && message) {

        msgEl.textContent = message;

    }

    const topTitle = document.getElementById('topbar-active-title');

    if (topTitle) topTitle.textContent = "403 Unauthorized";

    updateUrlPath('/unauthorized');

}



function goToMyRoleDashboard() {

    if (!state.user) {

        logoutUser(false);

        return;

    }

    routeUserByRole(true);

}



function handleUrlRouting() {

    const rawPath = window.location.pathname.toLowerCase();

    const path = rawPath.replace(/\/$/, '') || '/';



    if (state.authStatus === 'AUTHENTICATED' && state.user) {

        renderLayoutForAuth();

        const role = (state.user.role || '').toUpperCase();



        if (path === '/' || path === '/dashboard' || path === '/login' || path === '/about') {

            // Redirect authenticated user to canonical role dashboard

            routeUserByRole(true);

            return;

        }



        if (path.startsWith('/admin')) {

            if (role === 'ADMIN') {

                switchTab('admin', false);

                if (path === '/admin/users') switchAdminSubpanel('users');

                else if (path === '/admin/audit') switchAdminSubpanel('audit');

                updateUrlPath(rawPath);

            } else {

                showUnauthorizedView(`Access Denied: Role '${role}' is not authorized to access the Administrator Control Center.`);

            }

            return;

        }



        if (path.startsWith('/analyst')) {

            if (role === 'ADMIN' || role === 'ANALYST') {

                if (path === '/analyst/history') switchTab('analysis', false);

                else switchTab(state.sampleData ? 'analysis' : 'home', false);

                updateUrlPath(rawPath);

            } else {

                showUnauthorizedView(`Access Denied: Student accounts cannot access the full SOC Analyst Dashboard.`);

            }

            return;

        }



        if (path.startsWith('/student')) {

            switchTab('learning', false);

            updateUrlPath(rawPath);

            return;

        }



        // Protected static analysis sub-views

        const viewMap = {

            '/analysis': 'analysis',

            '/pe-analysis': 'pe-analysis',

            '/imports': 'imports',

            '/strings': 'strings',

            '/indicators': 'indicators',

            '/ai-analysis': 'ai-analyst',

            '/reports': 'reports',

            '/settings': role === 'ADMIN' ? 'admin' : null,

        };



        if (viewMap[path]) {

            switchTab(viewMap[path], false);

            updateUrlPath(rawPath);

            return;

        } else if (path === '/settings') {

            showUnauthorizedView("Access Denied: Platform Security Settings are restricted to Administrators.");

            return;

        } else if (path === '/unauthorized') {

            showUnauthorizedView();

            return;

        }

    } else {

        // UNAUTHENTICATED: Only render the Public Layout / Login Page

        renderLayoutForAuth();

        if (path !== '/login') {

            updateUrlPath('/login');

        }

        switchAuthTab('login');

    }

}



function routeUserByRole(updateUrl = true) {

    if (!state.user) return;

    const role = (state.user.role || '').toUpperCase();

    if (role === 'ADMIN') {

        switchTab('admin', updateUrl);

        if (updateUrl) updateUrlPath('/admin/dashboard');

    } else if (role === 'ANALYST') {

        switchTab(state.sampleData ? 'analysis' : 'home', updateUrl);

        if (updateUrl) updateUrlPath('/analyst/dashboard');

    } else if (role === 'STUDENT') {

        switchTab('learning', updateUrl);

        if (updateUrl) updateUrlPath('/student/dashboard');

    } else {

        showUnauthorizedView(`Unknown user role: '${role}'. Access restricted.`);

    }

}



function renderUserAuthWidget() {

    const profilePill = document.getElementById('user-profile-pill');

    const nameText = document.getElementById('user-display-name');

    const roleBadge = document.getElementById('user-role-badge');

    const navAdmin = document.getElementById('nav-item-admin');

    const roleBanner = document.getElementById('role-workspace-banner');

    const bannerIcon = document.getElementById('role-banner-icon');

    const bannerTitle = document.getElementById('role-banner-title');

    const bannerDesc = document.getElementById('role-banner-desc');

    const isAm = state.currentLanguage === 'am';



    if (state.user && state.authStatus === 'AUTHENTICATED') {

        if (profilePill) profilePill.style.display = 'flex';

        if (nameText) nameText.textContent = state.user.username;

        if (roleBadge) {

            roleBadge.textContent = state.user.role;

            roleBadge.className = 'role-badge';

            if (state.user.role === 'ADMIN') roleBadge.classList.add('role-badge-admin');

            else if (state.user.role === 'ANALYST') roleBadge.classList.add('role-badge-analyst');

            else roleBadge.classList.add('role-badge-student');

        }

        if (roleBanner) {

            roleBanner.style.display = 'flex';

            roleBanner.className = 'role-workspace-banner';

            if (state.user.role === 'ADMIN') {

                roleBanner.classList.add('banner-admin');

                if (bannerIcon) bannerIcon.textContent = '­ƒøí´©Å';

                if (bannerTitle) bannerTitle.textContent = isAm ? 'ßï¿ßèáßêÁßë░ßï│ßï│ßê¬ ßêøßïòßè¿ßêì ßîêßëóßê¡ ßèÉßïì (Administrator Control Active)' : 'Administrator Control Center Active';

                if (bannerDesc) bannerDesc.textContent = isAm ? 'ßêÖßêë ßï¿ßêÁßê¡ßïôßëÁ ßëüßîÑßîÑßê¡: ßï¿ßë░ßîáßëâßêÜßïÄßë¢ ßêÜßèô ßèáßêÁßë░ßï│ßï░ßê¡ ßèÑßèô ßï¿ßï░ßêàßèòßèÉßëÁ ßèªßï▓ßëÁ ßêÿßïØßîêßëªßë¢ßìó' : 'Full platform access: manage users, configure RBAC permissions, and view audit trail logs.';

            } else if (state.user.role === 'ANALYST') {

                roleBanner.classList.add('banner-analyst');

                if (bannerIcon) bannerIcon.textContent = '­ƒöì';

                if (bannerTitle) bannerTitle.textContent = isAm ? 'ßï¿ SOC ßêÁßîïßëÁ ßëÁßèòßë░ßèô ßï¿ßêÁßê½ ßëªßë│ (SOC Threat Analysis Active)' : 'SOC Threat Analysis Workspace Active';

                if (bannerDesc) bannerDesc.textContent = isAm ? 'ßï¿ßêøßêìßïîßê¡ ßêÁßîïßëÁ ßëÁßèòßë░ßèô: PE ßêÿßïïßëàßê¡ßìú ßï¿ entropy ßêÁßêîßëÁßìú ßî¢ßêüßìÄßë¢ ßèÑßèô ßï¿ßï░ßêàßèòßèÉßëÁ ßê¬ßìûßê¡ßëÁ ßêøßêÿßèòßî¿ßëÁßìó' : 'Operational malware triage: static PE inspection, entropy analysis, string extraction, and report generation.';

            } else {

                roleBanner.classList.add('banner-student');

                if (bannerIcon) bannerIcon.textContent = '­ƒÄô';

                if (bannerTitle) bannerTitle.textContent = isAm ? 'ßï¿ßë░ßêøßê¬ßïÄßë¢ ßï¿ßê│ßï¡ßëáßê¡ ßï░ßêàßèòßèÉßëÁ ßëÁßêØßêàßê¡ßëÁ ßëñßëÁ (Student Lab Active)' : 'Cybersecurity Student Learning Lab Active';

                if (bannerDesc) bannerDesc.textContent = isAm ? 'ßëáßï¡ßèÉßë░ßîêßèôßèØ ßï¿ reverse engineering ßëÁßêØßêàßê¡ßëÂßë¢ßìú ßï¿ßìàßèòßê░-ßêÇßê│ßëÑ ßêøßëÑßê½ßê¬ßï½ßïÄßë¢ ßèÑßèô ßï¿ßèôßêÖßèô ßêìßêØßêØßïÂßë¢ßìó' : 'Interactive educational reverse-engineering lessons, concept breakdowns, and safe sample practice.';

            }

        }

    } else {

        if (profilePill) profilePill.style.display = 'none';

        if (navAdmin) navAdmin.style.display = 'none';

        if (roleBanner) roleBanner.style.display = 'none';

    }

}



async function logoutUser(callApi = true) {

    if (callApi && state.token) {

        try {

            await fetch('/api/auth/logout', {

                method: 'POST',

                headers: { 'Authorization': `Bearer ${state.token}` }

            });

        } catch (e) {

            console.warn('Logout request failed:', e);

        }

    }

    state.user = null;

    state.token = null;

    state.authStatus = 'UNAUTHENTICATED';

    localStorage.removeItem('ethio_auth_token');

    renderLayoutForAuth();

    renderUserAuthWidget();

    renderNavigationForRole();

    updateUrlPath('/login');

    switchAuthTab('login');

}



/**

 * Administration & SOC Security Management (Module 16 & 17)

 */

state.adminUsersList = [];

state.adminCurrentSubtab = 'overview';



function switchAdminTab(subtab) {

    state.adminCurrentSubtab = subtab;

    const tabs = ['overview', 'users', 'rbac', 'audit', 'system'];



    tabs.forEach(t => {

        const btn = document.getElementById(`admin-subtab-${t}`);

        const panel = document.getElementById(`admin-panel-${t}`);

        if (btn) btn.classList.toggle('active', t === subtab);

        if (panel) panel.style.display = (t === subtab) ? 'block' : 'none';

    });



    if (subtab === 'overview') {

        loadAdminOverview();

    } else if (subtab === 'users') {

        loadUsersList();

    } else if (subtab === 'rbac') {

        loadRbacMatrix();

    } else if (subtab === 'audit') {

        loadAuditLogs();

    } else if (subtab === 'system') {

        loadSystemStatus();

    }

}



async function loadAdminOverview() {

    if (!state.user || state.user.role !== 'ADMIN') return;



    try {

        const res = await fetchWithAuth('/api/auth/overview');

        if (!res || !res.ok) return;

        const data = await res.json();



        // 1. Animate 6 Hero KPI Counters

        animateCounter('admin-overview-users-total', data.total_users || 0);

        animateCounter('admin-overview-active-users', data.active_users || 0);

        animateCounter('admin-overview-samples-total', data.total_samples || 0);

        animateCounter('admin-overview-high-risk', data.high_risk_samples || 0);

        animateCounter('admin-overview-critical', data.critical_risk_samples || 0);



        const usersBreakdownEl = document.getElementById('admin-overview-users-breakdown');

        if (usersBreakdownEl) {

            usersBreakdownEl.textContent = `${data.admin_count || 0} Admins ÔÇó ${data.analyst_count || 0} Analysts ÔÇó ${data.student_count || 0} Students`;

        }



        const indicatorsTotalEl = document.getElementById('admin-overview-indicators-total');

        if (indicatorsTotalEl) {

            indicatorsTotalEl.textContent = `${data.total_indicators || 0} Correlated Indicators`;

        }



        const healthEl = document.getElementById('admin-overview-health');

        if (healthEl) {

            healthEl.textContent = data.system_health || 'OPTIMAL';

        }



        // 2. Animate Risk Distribution Chart Bars

        const totalSamples = Math.max(1, data.total_samples || 0);

        const lowCount = data.low_risk_samples || 0;

        const medCount = data.medium_risk_samples || 0;

        const highCount = data.high_risk_samples || 0;

        const critCount = data.critical_risk_samples || 0;



        animateCounter('dist-count-low', lowCount);

        animateCounter('dist-count-medium', medCount);

        animateCounter('dist-count-high', highCount);

        animateCounter('dist-count-crit', critCount);



        const lowBar = document.getElementById('dist-bar-low');

        const medBar = document.getElementById('dist-bar-medium');

        const highBar = document.getElementById('dist-bar-high');

        const critBar = document.getElementById('dist-bar-crit');



        if (lowBar) lowBar.style.width = `${Math.round((lowCount / totalSamples) * 100)}%`;

        if (medBar) medBar.style.width = `${Math.round((medCount / totalSamples) * 100)}%`;

        if (highBar) highBar.style.width = `${Math.round((highCount / totalSamples) * 100)}%`;

        if (critBar) critBar.style.width = `${Math.round((critCount / totalSamples) * 100)}%`;



        // 3. Render Recent Provisioned Users

        const tbody = document.getElementById('admin-recent-users-tbody');

        if (tbody) {

            if (!data.recent_users || data.recent_users.length === 0) {

                tbody.innerHTML = '<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="4" class="empty-state-cell">No users registered yet.</td></tr>';

            } else {

                tbody.innerHTML = data.recent_users.map(u => {

                    const roleBadgeClass = u.role === 'ADMIN' ? 'role-badge-admin' : (u.role === 'ANALYST' ? 'role-badge-analyst' : 'role-badge-student');

                    const dateStr = u.created_at ? u.created_at.replace('T', ' ').substring(0, 10) : '-';

                    return `

                        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                            <td style="font-weight: 600; color: var(--text-primary);">

                                ${escapeHtml(u.username)} ${state.user && u.id === state.user.id ? '<span style="font-size: 10px; color: var(--accent-cyan); font-weight: 700;">(You)</span>' : ''}

                            </td>

                            <td><span class="role-badge ${roleBadgeClass}">${escapeHtml(u.role)}</span></td>

                            <td><span class="badge ${u.is_active ? 'badge-low' : 'badge-crit'}">${u.is_active ? 'ACTIVE' : 'INACTIVE'}</span></td>

                            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(dateStr)}</td>

                        </tr>

                    `;

                }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

            }

        }

    } catch (err) {

        console.warn('Error loading admin overview:', err);

    }

}



async function loadUsersList() {

    if (!state.user || state.user.role !== 'ADMIN') return;

    const tbody = document.getElementById('admin-users-tbody');

    if (!tbody) return;



    try {

        const res = await fetchWithAuth('/api/auth/users');

        if (!res || !res.ok) {

            tbody.innerHTML = '<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">Access denied or failed to load users.</td></tr>';

            return;

        }

        state.adminUsersList = await res.json();

        const countBadge = document.getElementById('admin-users-count-badge');

        if (countBadge) countBadge.textContent = `${state.adminUsersList.length} platform identity record${state.adminUsersList.length === 1 ? '' : 's'}`;

        filterUsersTable();

    } catch (err) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;

    }

}



function filterUsersTable() {

    const tbody = document.getElementById('admin-users-tbody');

    if (!tbody) return;



    const query = (document.getElementById('admin-users-search')?.value || '').toLowerCase().trim();

    const roleFilter = (document.getElementById('admin-users-filter-role')?.value || '').toUpperCase();

    const statusFilter = (document.getElementById('admin-users-filter-status')?.value || '').toUpperCase();



    let users = state.adminUsersList || [];



    if (query) {

        users = users.filter(u => 

            (u.username || '').toLowerCase().includes(query) || 

            (u.email || '').toLowerCase().includes(query)

        );

    }

    if (roleFilter) {

        users = users.filter(u => (u.role || '').toUpperCase() === roleFilter);

    }

    if (statusFilter === 'ACTIVE') {

        users = users.filter(u => u.is_active && !u.is_locked);

    } else if (statusFilter === 'INACTIVE') {

        users = users.filter(u => !u.is_active);

    } else if (statusFilter === 'LOCKED') {

        users = users.filter(u => u.is_locked || (u.failed_attempts && u.failed_attempts >= 5));

    }



    if (users.length === 0) {

        tbody.innerHTML = '<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">No matching platform users found.</td></tr>';

        return;

    }



    tbody.innerHTML = users.map(u => {

        const isCurrent = state.user && state.user.id === u.id;

        const roleBadgeClass = u.role === 'ADMIN' ? 'role-badge-admin' : (u.role === 'ANALYST' ? 'role-badge-analyst' : 'role-badge-student');

        

        let statusBadge = u.is_active 

            ? '<span class="badge badge-low">ACTIVE</span>' 

            : '<span class="badge badge-crit">DEACTIVATED</span>';



        const isLocked = u.is_locked || (u.failed_attempts && u.failed_attempts >= 5);

        if (isLocked) {

            statusBadge = '<span class="badge badge-high" title="Account locked due to failed attempts">­ƒöÆ LOCKED</span>';

        }



        const roleModalBtn = isCurrent ? '' : `

            <button class="btn-secondary" data-action="role-modal" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}" data-role="${escapeHtml(u.role)}" style="font-size: 10px; padding: 2px 6px;" title="Change user role">

                ­ƒÄ¡ Role

            </button>

        `;



        const resetPassBtn = `

            <button class="btn-secondary" data-action="reset-pass" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}" style="font-size: 10px; padding: 2px 6px;" title="Reset password">

                ­ƒöæ Password

            </button>

        `;



        const unlockBtn = isLocked ? `

            <button class="btn-secondary" data-action="unlock-user" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}" style="font-size: 10px; padding: 2px 6px; color: var(--accent-blue); border-color: var(--accent-blue);" title="Clear failed attempts and unlock">

                ­ƒöô Unlock

            </button>

        ` : '';



        const toggleBtn = isCurrent ? '' : `

            <button class="btn-secondary" data-action="toggle-status" data-user-id="${u.id}" style="font-size: 10px; padding: 2px 6px;" title="${u.is_active ? 'Deactivate user' : 'Activate user'}">

                ${u.is_active ? 'ÔÅ©´©Å' : 'ÔûÂ´©Å'}

            </button>

        `;



        const deleteBtn = isCurrent ? '' : `

            <button class="btn-secondary" data-action="delete-user" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}" style="font-size: 10px; padding: 2px 6px; color: #f87171; border-color: rgba(239,68,68,0.3);" title="Delete user">

                ­ƒùæ´©Å

            </button>

        `;



        return `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td style="font-family: var(--font-mono); font-weight: 600; font-size: 11px;">#${u.id}</td>

                <td style="font-weight: 600; color: var(--text-primary);">

                    ${escapeHtml(u.username)} ${isCurrent ? '<span style="font-size: 10px; color: var(--accent-blue); font-weight: 700;">(You)</span>' : ''}

                </td>

                <td style="color: var(--text-secondary); font-size: 12px;">${escapeHtml(u.email)}</td>

                <td><span class="role-badge ${roleBadgeClass}">${escapeHtml(u.role)}</span></td>

                <td>${statusBadge}</td>

                <td>

                    <span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${u.permissions ? u.permissions.length : 0} permissions</span>

                </td>

                <td style="text-align: right;">

                    <div style="display: flex; gap: 4px; justify-content: flex-end; align-items: center;">

                        ${unlockBtn}

                        ${roleModalBtn}

                        ${resetPassBtn}

                        ${toggleBtn}

                        ${deleteBtn}

                    </div>

                </td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

}



function openAdminRoleModal(userId, username, currentRole) {

    const modal = document.getElementById('admin-role-modal');

    const idInput = document.getElementById('admin-role-user-id');

    const userDisplay = document.getElementById('admin-role-username-display');

    const selectEl = document.getElementById('admin-role-select');

    if (!modal) return;

    if (idInput) idInput.value = userId;

    if (userDisplay) userDisplay.textContent = username;

    if (selectEl) selectEl.value = currentRole;

    modal.style.display = 'flex';

}



function closeAdminRoleModal() {

    const modal = document.getElementById('admin-role-modal');

    if (modal) modal.style.display = 'none';

}



async function handleAdminUpdateRoleSubmit(event) {

    event.preventDefault();

    const userId = document.getElementById('admin-role-user-id')?.value;

    const newRole = document.getElementById('admin-role-select')?.value;

    if (!userId || !newRole) return;



    try {

        const res = await fetchWithAuth(`/api/auth/users/${userId}/role`, {

            method: 'PUT',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ role: newRole })

        });

        const data = await res.json();

        if (!res.ok) {

            alert('Failed to update role: ' + (data.detail || res.statusText));

            return;

        }

        closeAdminRoleModal();

        await loadUsersList();

        await loadAdminOverview();

    } catch (err) {

        alert('Error updating role: ' + err.message);

    }

}




function handleAdminUsersTableClick(event) {
    const btn = event.target.closest('[data-action]');
    if (!btn) return;

    const action = btn.dataset.action;
    const userId = parseInt(btn.dataset.userId, 10);
    const username = btn.dataset.username;
    const role = btn.dataset.role;

    if (isNaN(userId)) return;

    if (action === 'role-modal') {
        openAdminRoleModal(userId, username, role);
    } else if (action === 'reset-pass') {
        openAdminResetPassModal(userId, username);
    } else if (action === 'unlock-user') {
        handleAdminUnlockUser(userId, username);
    } else if (action === 'toggle-status') {
        toggleUserStatus(userId);
    } else if (action === 'delete-user') {
        deleteUserAccount(userId, username);
    }
}

function openAdminResetPassModal(userId, username) {

    const modal = document.getElementById('admin-reset-pass-modal');

    const idInput = document.getElementById('admin-reset-user-id');

    const userDisplay = document.getElementById('admin-reset-username-display');

    const passInput = document.getElementById('admin-reset-new-pass');

    if (!modal) return;

    if (idInput) idInput.value = userId;

    if (userDisplay) userDisplay.textContent = username;

    if (passInput) passInput.value = '';

    modal.style.display = 'flex';

}



function closeAdminResetPassModal() {

    const modal = document.getElementById('admin-reset-pass-modal');

    if (modal) modal.style.display = 'none';

}



async function handleAdminResetPassSubmit(event) {

    event.preventDefault();

    const userId = document.getElementById('admin-reset-user-id')?.value;

    const password = document.getElementById('admin-reset-new-pass')?.value;

    if (!userId || !password) return;



    try {

        const res = await fetchWithAuth(`/api/auth/users/${userId}/reset-password`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ password })

        });

        const data = await res.json();

        if (!res.ok) {

            alert('Failed to reset password: ' + (data.detail || res.statusText));

            return;

        }

        alert(data.message || 'Password successfully updated.');

        closeAdminResetPassModal();

    } catch (err) {

        alert('Error resetting password: ' + err.message);

    }

}



async function handleAdminUnlockUser(userId, username) {

    if (!confirm(`Unlock account '${username}' and clear failed attempt counters?`)) return;

    try {

        const res = await fetchWithAuth(`/api/auth/users/${userId}/unlock`, {

            method: 'POST'

        });

        const data = await res.json();

        if (!res.ok) {

            alert('Failed to unlock account: ' + (data.detail || res.statusText));

            return;

        }

        alert(data.message || 'User account successfully unlocked.');

        await loadUsersList();

        await loadAdminOverview();

    } catch (err) {

        alert('Error unlocking user: ' + err.message);

    }

}



function toggleNewUserForm(show) {

    const card = document.getElementById('admin-create-user-card');

    const errBox = document.getElementById('admin-create-user-err');

    if (errBox) errBox.style.display = 'none';

    if (card) {

        card.style.display = show ? 'block' : 'none';

        if (show) {

            document.getElementById('admin-new-username')?.focus();

        }

    }

}



async function handleAdminCreateUser(event) {

    event.preventDefault();

    const errBox = document.getElementById('admin-create-user-err');

    const username = (document.getElementById('admin-new-username')?.value || '').trim();

    const email = (document.getElementById('admin-new-email')?.value || '').trim();

    const password = document.getElementById('admin-new-password')?.value || '';

    const role = document.getElementById('admin-new-role')?.value || 'STUDENT';



    if (errBox) errBox.style.display = 'none';



    try {

        const res = await fetchWithAuth('/api/auth/users', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ username, email, password, role })

        });

        const data = await res.json();

        if (!res.ok) {

            if (errBox) {

                errBox.textContent = data.detail || 'Failed to provision user.';

                errBox.style.display = 'block';

            }

            return;

        }



        // Reset form & reload

        document.getElementById('admin-create-user-form')?.reset();

        toggleNewUserForm(false);

        await loadUsersList();

        await loadAdminOverview();

    } catch (err) {

        if (errBox) {

            errBox.textContent = 'Server error: ' + err.message;

            errBox.style.display = 'block';

        }

    }

}



async function toggleUserStatus(userId) {

    try {

        const res = await fetchWithAuth(`/api/auth/users/${userId}/status`, {

            method: 'PUT'

        });

        if (!res || !res.ok) {

            const data = await res.json();

            alert('Failed to toggle status: ' + (data.detail || res.statusText));

            return;

        }

        await loadUsersList();

        await loadAdminOverview();

    } catch (err) {

        alert('Error updating user status: ' + err.message);

    }

}



async function deleteUserAccount(userId, username) {

    if (!confirm(`Are you sure you want to permanently delete user account '${username}'? This action cannot be undone.`)) {

        return;

    }

    try {

        const res = await fetchWithAuth(`/api/auth/users/${userId}`, {

            method: 'DELETE'

        });

        if (!res || !res.ok) {

            const data = await res.json();

            alert('Failed to delete user: ' + (data.detail || res.statusText));

            return;

        }

        await loadUsersList();

        await loadAdminOverview();

    } catch (err) {

        alert('Error deleting user: ' + err.message);

    }

}



/**

 * RBAC Matrix Rendering

 */

async function loadRbacMatrix() {

    const tbody = document.getElementById('admin-rbac-tbody');

    if (!tbody) return;



    try {

        const res = await fetchWithAuth('/api/auth/rbac/matrix');

        if (!res || !res.ok) {

            tbody.innerHTML = '<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="5" class="empty-state-cell">Unable to load RBAC permissions matrix.</td></tr>';

            return;

        }

        const data = await res.json();

        const matrix = data.matrix || {};

        const permissions = data.permissions || [];



        const adminPerms = new Set(matrix['ADMIN'] || []);

        const analystPerms = new Set(matrix['ANALYST'] || []);

        const studentPerms = new Set(matrix['STUDENT'] || []);



        tbody.innerHTML = permissions.map(p => {

            const hasAdmin = adminPerms.has(p.id);

            const hasAnalyst = analystPerms.has(p.id);

            const hasStudent = studentPerms.has(p.id);



            return `

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td style="font-weight: 600; color: var(--text-primary);">

                        <code>${escapeHtml(p.id)}</code>

                    </td>

                    <td style="font-size: 12px; color: var(--text-secondary);">

                        ${escapeHtml(p.description)}

                    </td>

                    <td style="text-align: center;">

                        ${hasAdmin ? '<span style="color: #10b981; font-weight: 700; font-size: 14px;">Ô£ô Granted</span>' : '<span style="color: var(--text-muted);">ÔÇö</span>'}

                    </td>

                    <td style="text-align: center;">

                        ${hasAnalyst ? '<span style="color: #06b6d4; font-weight: 700; font-size: 14px;">Ô£ô Granted</span>' : '<span style="color: var(--text-muted);">ÔÇö</span>'}

                    </td>

                    <td style="text-align: center;">

                        ${hasStudent ? '<span style="color: #10b981; font-weight: 700; font-size: 14px;">Ô£ô Granted</span>' : '<span style="color: var(--text-muted);">ÔÇö</span>'}

                    </td>

                </tr>

            `;

        }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

    } catch (err) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="5" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;

    }

}



/**

 * System Status & Sandbox Quarantine Controller

 */

async function loadSystemStatus() {

    try {

        const res = await fetchWithAuth('/api/auth/system/status');

        if (!res || !res.ok) return;

        const data = await res.json();



        const qBytesEl = document.getElementById('sys-status-quarantine-bytes');

        const qSubEl = document.getElementById('sys-status-quarantine-sub');

        const dbBytesEl = document.getElementById('sys-status-db-bytes');

        const dbSubEl = document.getElementById('sys-status-db-sub');



        if (qBytesEl) qBytesEl.textContent = formatBytes(data.quarantine_bytes || 0);

        if (qSubEl) qSubEl.textContent = `${data.quarantine_count || 0} quarantined payloads in storage/quarantine`;

        if (dbBytesEl) dbBytesEl.textContent = formatBytes(data.database_bytes || 0);

        if (dbSubEl) dbSubEl.textContent = `${data.database_samples_count || 0} sample rows ÔÇó ${data.audit_logs_count || 0} audit logs`;

    } catch (err) {

        console.warn('Could not load system status:', err);

    }

}



async function purgeQuarantineCache() {

    if (!confirm('Purge temporary quarantine buffer files? Note: Active analysis database records will NOT be deleted.')) return;

    try {

        const res = await fetchWithAuth('/api/auth/system/quarantine/cleanup', {

            method: 'POST'

        });

        const data = await res.json();

        alert(data.message || 'Quarantine cache purged.');

        loadSystemStatus();

    } catch (err) {

        alert('Error purging quarantine cache: ' + err.message);

    }

}



/**

 * Security Audit Trail & SIEM Export

 */

function openAuditDetailModal(encodedDetails) {

    const modal = document.getElementById('admin-audit-modal');

    const content = document.getElementById('admin-audit-modal-content');

    if (!modal || !content) return;

    try {

        const detailsObj = JSON.parse(decodeURIComponent(encodedDetails));

        content.textContent = JSON.stringify(detailsObj, null, 2);

    } catch (e) {

        content.textContent = decodeURIComponent(encodedDetails);

    }

    modal.style.display = 'flex';

}



function closeAuditDetailModal() {

    const modal = document.getElementById('admin-audit-modal');

    if (modal) modal.style.display = 'none';

}



let auditSearchTimeout = null;

function handleAuditSearch(event) {

    clearTimeout(auditSearchTimeout);

    auditSearchTimeout = setTimeout(() => {

        loadAuditLogs();

    }, 350);

}



async function loadAuditLogs() {

    if (!state.user || state.user.role !== 'ADMIN') return;



    const tbody = document.getElementById('audit-logs-tbody');

    const eventFilter = (document.getElementById('audit-filter-event') || {}).value || '';

    const resultFilter = (document.getElementById('audit-filter-result') || {}).value || '';

    const searchInput = (document.getElementById('audit-search-input') || {}).value || '';



    // Fetch Stats

    try {

        const statsRes = await fetchWithAuth('/api/audit/stats');

        if (statsRes && statsRes.ok) {

            const stats = await statsRes.json();

            const totalEl = document.getElementById('audit-stat-total');

            const successEl = document.getElementById('audit-stat-success');

            const failuresEl = document.getElementById('audit-stat-failures');

            const deniedEl = document.getElementById('audit-stat-denied');



            if (totalEl) totalEl.textContent = stats.total_events || 0;

            if (successEl) successEl.textContent = stats.success_count || 0;

            if (failuresEl) failuresEl.textContent = (stats.failure_count || 0) + (stats.lockout_count || 0);

            if (deniedEl) deniedEl.textContent = stats.denied_count || 0;

        }

    } catch (e) {

        console.warn('Could not load audit stats:', e);

    }



    // Fetch Logs

    try {

        const params = new URLSearchParams();

        if (eventFilter) params.append('event', eventFilter);

        if (resultFilter) params.append('result', resultFilter);

        if (searchInput.trim()) params.append('search', searchInput.trim());

        params.append('page_size', '50');



        const logsRes = await fetchWithAuth(`/api/audit/logs?${params.toString()}`);

        if (!logsRes || !logsRes.ok) {

            if (tbody) tbody.innerHTML = '<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">Access denied or failed to load audit logs.</td></tr>';

            return;

        }



        const data = await logsRes.json();

        if (!data.items || data.items.length === 0) {

            if (tbody) tbody.innerHTML = '<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">No matching audit events recorded yet.</td></tr>';

            return;

        }



        if (tbody) {

            tbody.innerHTML = data.items.map(item => {

                const resClass = getAuditResultBadgeClass(item.result);

                const userDisplay = item.username ? `${escapeHtml(item.username)} (#${item.user_id})` : (item.ip_address || 'System / Anon');

                const detailsEncoded = encodeURIComponent(JSON.stringify(item.details || {}));



                return `

                    <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                        <td style="font-family: var(--font-mono); font-size: 11px; white-space: nowrap;">

                            ${escapeHtml(item.timestamp ? item.timestamp.replace('T', ' ').substring(0, 19) : '')}

                        </td>

                        <td>

                            <span class="badge badge-low" style="font-size: 10px; font-weight: 700; text-transform: uppercase;">

                                ${escapeHtml(item.event)}

                            </span>

                        </td>

                        <td>

                            <span class="badge ${resClass}" style="font-size: 10px; font-weight: 700;">

                                ${escapeHtml(item.result)}

                            </span>

                        </td>

                        <td style="font-size: 12px; color: var(--text-primary);">

                            ${escapeHtml(userDisplay)}

                        </td>

                        <td style="font-family: var(--font-mono); font-size: 11px;">

                            ${item.analysis_id ? `<span style="color: var(--accent-blue);">${escapeHtml(item.analysis_id)}</span>` : '<span style="color: var(--text-muted);">-</span>'}

                        </td>

                        <td style="font-size: 11px; color: var(--text-secondary); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">

                            ${escapeHtml(JSON.stringify(item.details || {}))}

                        </td>

                        <td style="text-align: right;">

                            <button class="btn-secondary" data-action="audit-detail" data-details="${detailsEncoded}" style="font-size: 10px; padding: 2px 6px;">

                                ­ƒöì Inspect

                            </button>

                        </td>

                    </tr>

                `;

            }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

        }

    } catch (err) {

        if (tbody) tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;

    }

}




function handleAuditLogsTableClick(event) {
    const btn = event.target.closest('[data-action="audit-detail"]');
    if (!btn) return;
    const encodedDetails = btn.dataset.details;
    if (encodedDetails) {
        openAuditDetailModal(encodedDetails);
    }
}

function getAuditResultBadgeClass(result) {

    const r = (result || '').toUpperCase();

    if (r === 'SUCCESS') return 'badge-low';

    if (r === 'FAILURE' || r === 'ERROR') return 'badge-high';

    if (r === 'LOCKED' || r === 'DENIED') return 'badge-crit';

    return 'badge-mod';

}



async function exportAuditLogsCsv() {

    try {

        const res = await fetchWithAuth('/api/audit/export/csv');

        if (!res || !res.ok) {

            alert('Failed to export audit logs. Please make sure you are logged in as an Administrator.');

            return;

        }



        const blob = await res.blob();

        const url = window.URL.createObjectURL(blob);

        const a = document.createElement('a');

        a.style.display = 'none';

        a.href = url;

        a.download = `security_audit_export_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;

        document.body.appendChild(a);

        a.click();

        window.URL.revokeObjectURL(url);

        document.body.removeChild(a);

    } catch (err) {

        alert('Error exporting CSV: ' + err.message);

    }

}



async function exportAuditLogsJson() {

    try {

        const res = await fetchWithAuth('/api/audit/logs?page_size=500');

        if (!res || !res.ok) {

            alert('Failed to export SIEM JSON.');

            return;

        }

        const data = await res.json();

        const blob = new Blob([JSON.stringify(data.items || [], null, 2)], { type: 'application/json' });

        const url = window.URL.createObjectURL(blob);

        const a = document.createElement('a');

        a.style.display = 'none';

        a.href = url;

        a.download = `siem_audit_logs_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;

        document.body.appendChild(a);

        a.click();

        window.URL.revokeObjectURL(url);

        document.body.removeChild(a);

    } catch (err) {

        alert('Error exporting SIEM JSON: ' + err.message);

    }

}



/* ==========================================================================

   MODULE WORKSPACES: PE, IMPORTS, INDICATORS, AI ANALYST, AND REPORTS

   ========================================================================== */



/**

 * Universal Analysis ID Resolver

 * Tier 1: Explicit parameter

 * Tier 2: URL search param (?analysis_id=...)

 * Tier 3: state.activeAnalysisId

 * Tier 4: Most recent analysis from DB (/api/analyses?limit=1)

 */

async function resolveTargetAnalysisId(explicitId) {

    if (explicitId) return explicitId;



    const urlParam = new URLSearchParams(window.location.search).get('analysis_id');

    if (urlParam) return urlParam;



    if (state.activeAnalysisId) return state.activeAnalysisId;



    try {

        const res = await fetchWithAuth('/api/analyses?limit=1');

        if (res && res.ok) {

            const data = await res.json();

            if (data && data.items && data.items.length > 0) {

                return data.items[0].analysis_id;

            }

        }

    } catch (e) {

        console.warn('Could not auto-resolve latest analysis ID:', e);

    }



    return null;

}



/* --------------------------------------------------------------------------

   1. PORTABLE EXECUTABLE (PE) STRUCTURE WORKSPACE

   -------------------------------------------------------------------------- */



async function loadPeStructureAnalysis(analysisId) {

    const banner = document.getElementById('pe-no-analysis-banner');

    const container = document.getElementById('pe-content-container');

    const tbody = document.getElementById('pe-sections-tbody');



    const targetId = await resolveTargetAnalysisId(analysisId);

    if (!targetId) {

        if (banner) banner.style.display = 'block';

        if (container) container.style.display = 'none';

        return;

    }



    state.activeAnalysisId = targetId;

    if (banner) banner.style.display = 'none';

    if (container) container.style.display = 'block';

    if (tbody) tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="9" class="empty-state-cell">Loading PE headers and memory sections for ${escapeHtml(targetId)}...</td></tr>`;



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(targetId)}/pe`);

        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch PE structure`);

        const data = await res.json();



        state.peCurrentData = data;

        state.peCurrentSections = data.sections || [];



        // Update Ribbon

        const fnEl = document.getElementById('pe-active-filename');

        if (fnEl) fnEl.textContent = data.filename || 'sample.exe';

        const anlIdEl = document.getElementById('pe-active-analysis-id');

        if (anlIdEl) anlIdEl.textContent = data.analysis_id || targetId;

        const shaEl = document.getElementById('pe-active-sha256');

        if (shaEl) shaEl.textContent = data.sha256 || 'N/A';

        const cntEl = document.getElementById('pe-active-sections-counter');

        if (cntEl) cntEl.textContent = data.section_count || state.peCurrentSections.length;



        // Update Metrics Cards

        const archEl = document.getElementById('pe-metric-arch');

        if (archEl) archEl.textContent = data.architecture || 'x86_64';

        const subsysEl = document.getElementById('pe-metric-subsystem');

        if (subsysEl) subsysEl.textContent = data.subsystem || 'Windows GUI';

        const epEl = document.getElementById('pe-metric-entrypoint');

        if (epEl) epEl.textContent = data.entry_point || '0x00001000';

        const ibEl = document.getElementById('pe-metric-imagebase');

        if (ibEl) ibEl.textContent = `Image Base: ${data.image_base || '0x00400000'}`;



        const entValEl = document.getElementById('pe-metric-entropy');

        if (entValEl) entValEl.textContent = `${(data.file_entropy || 0).toFixed(2)} / 8.00`;

        const entSubEl = document.getElementById('pe-metric-entropy-class');

        if (entSubEl) entSubEl.textContent = data.entropy_classification || 'Normal';



        const wxValEl = document.getElementById('pe-metric-wx-val');

        const wxSubEl = document.getElementById('pe-metric-wx-sub');

        const wxCard = document.getElementById('pe-metric-wx-card');

        if (data.has_wx_sections) {

            if (wxValEl) { wxValEl.textContent = 'DANGER: RWX Detected'; wxValEl.style.color = 'var(--sev-crit)'; }

            if (wxSubEl) wxSubEl.textContent = 'Executable & Writable Memory';

            if (wxCard) wxCard.style.borderTop = '2px solid var(--sev-crit)';

        } else {

            if (wxValEl) { wxValEl.textContent = '0 Detected'; wxValEl.style.color = '#10b981'; }

            if (wxSubEl) wxSubEl.textContent = 'Safe Memory Permissions';

            if (wxCard) wxCard.style.borderTop = 'none';

        }



        // Update Grids

        const pSub = document.getElementById('pe-subsystem');

        if (pSub) pSub.textContent = data.subsystem || 'Windows GUI';

        const pEp = document.getElementById('pe-entry-point');

        if (pEp) pEp.textContent = data.entry_point || '0x00001000';

        const pIb = document.getElementById('pe-image-base');

        if (pIb) pIb.textContent = data.image_base || '0x00400000';

        const pCt = document.getElementById('pe-compile-time');

        if (pCt) pCt.textContent = data.compilation_time ? data.compilation_time.replace('T', ' ').substring(0, 19) : 'N/A';

        const pFmt = document.getElementById('pe-file-format');

        if (pFmt) pFmt.textContent = `${data.file_type || 'PE32+'} (${data.architecture || 'x64'})`;

        const pTot = document.getElementById('pe-total-sections');

        if (pTot) pTot.textContent = `${data.section_count || state.peCurrentSections.length} sections`;



        const pFe = document.getElementById('pe-file-entropy');

        if (pFe) pFe.textContent = `${(data.file_entropy || 0).toFixed(2)} / 8.00`;

        const pMe = document.getElementById('pe-max-entropy');

        if (pMe) pMe.textContent = `${(data.max_section_entropy || 0).toFixed(2)} / 8.00`;

        const pEc = document.getElementById('pe-entropy-class');

        if (pEc) {

            const isHigh = (data.file_entropy || 0) >= 7.0;

            pEc.innerHTML = `<span class="badge ${isHigh ? 'badge-high' : 'badge-low'}">${escapeHtml(data.entropy_classification || 'NORMAL')}</span>`;

        }

        const pWx = document.getElementById('pe-wx-status');

        if (pWx) {

            pWx.innerHTML = data.has_wx_sections

                ? `<span class="badge badge-crit">RWX Present</span>`

                : `<span class="badge badge-low">Clean</span>`;

        }



        const badgeCount = document.getElementById('pe-sections-count-badge');

        if (badgeCount) badgeCount.textContent = `${state.peCurrentSections.length} SECTIONS`;



        renderPeSectionsTable(state.peCurrentSections);

    } catch (err) {

        if (tbody) tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="9" class="empty-state-cell" style="color: var(--sev-high);">Failed to load PE data: ${escapeHtml(err.message)}</td></tr>`;

    }

}



function renderPeSectionsTable(sections) {

    const tbody = document.getElementById('pe-sections-tbody');

    if (!tbody) return;



    if (!sections || sections.length === 0) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="9" class="empty-state-cell">No memory sections found for this binary.</td></tr>`;

        return;

    }



    tbody.innerHTML = sections.map((sec, idx) => {

        const ent = sec.entropy || 0;

        const entPct = Math.min(100, Math.max(0, (ent / 8.0) * 100));

        let entColor = '#10b981';

        if (ent >= 7.2) entColor = '#ef4444';

        else if (ent >= 6.5) entColor = '#f59e0b';



        let permBadges = '';

        if (sec.is_rwx) {

            permBadges = `<span class="badge badge-crit" title="Executable & Writable Memory">RWX</span>`;

        } else {

            const flags = [];

            if (sec.is_executable) flags.push('<span class="badge badge-high" style="padding: 2px 4px; font-size: 10px;">X</span>');

            if (sec.is_writable) flags.push('<span class="badge badge-mod" style="padding: 2px 4px; font-size: 10px;">W</span>');

            if (sec.characteristics && sec.characteristics.includes('READ')) flags.push('<span class="badge badge-low" style="padding: 2px 4px; font-size: 10px;">R</span>');

            permBadges = flags.join(' ') || '<span class="badge badge-rule">R</span>';

        }



        const statusBadge = (sec.entropy_status === 'SUSPICIOUS' || sec.is_rwx)

            ? `<span class="badge badge-crit">SUSPICIOUS</span>`

            : (sec.entropy_status === 'ELEVATED' ? `<span class="badge badge-high">ELEVATED</span>` : `<span class="badge badge-low">NORMAL</span>`);



        return `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td style="text-align: center; color: var(--text-muted); font-size: 11px;">${idx + 1}</td>

                <td><code style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">${escapeHtml(sec.name || '.sec')}</code></td>

                <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(sec.virtual_address || '0x00000000')}</td>

                <td style="font-size: 11px;">${escapeHtml(sec.virtual_size_formatted || `${sec.virtual_size || 0} bytes`)}</td>

                <td style="font-size: 11px;">${escapeHtml(sec.raw_size_formatted || `${sec.raw_size || 0} bytes`)}</td>

                <td>

                    <div style="display: flex; align-items: center; gap: 8px;">

                        <span style="font-family: var(--font-mono); font-size: 11px; width: 34px;">${ent.toFixed(2)}</span>

                        <div style="flex: 1; height: 6px; background: rgba(255,255,255,0.08); border-radius: 3px; overflow: hidden;">

                            <div style="width: ${entPct}%; height: 100%; background: ${entColor}; border-radius: 3px;"></div>

                        </div>

                    </div>

                </td>

                <td>${permBadges}</td>

                <td>${statusBadge}</td>

                <td style="text-align: center;">

                    <button class="btn-secondary" onclick="openPeSectionDetailModal(${idx})" style="font-size: 11px; padding: 2px 8px;" title="Inspect section forensic details">

                        ­ƒöì Inspect

                    </button>

                </td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

}



function openPeSectionDetailModal(idx) {

    const sec = (state.peCurrentSections || [])[idx];

    if (!sec) return;



    state.activeInspectedSection = sec;

    const modal = document.getElementById('pe-section-detail-modal');

    if (!modal) return;



    document.getElementById('pe-modal-sec-name').textContent = sec.name || '-';

    document.getElementById('pe-modal-sec-va').textContent = sec.virtual_address || '0x00000000';

    document.getElementById('pe-modal-sec-vsize').textContent = sec.virtual_size_formatted || `${sec.virtual_size} bytes`;

    document.getElementById('pe-modal-sec-rawsize').textContent = sec.raw_size_formatted || `${sec.raw_size} bytes`;



    const ent = sec.entropy || 0;

    const badge = document.getElementById('pe-modal-sec-entropy-badge');

    const bar = document.getElementById('pe-modal-sec-entropy-bar');

    const expl = document.getElementById('pe-modal-sec-entropy-explanation');



    if (badge) {

        badge.textContent = `${ent.toFixed(2)} / 8.00 (${sec.entropy_status || 'NORMAL'})`;

        badge.className = `badge ${ent >= 7.2 ? 'badge-crit' : (ent >= 6.5 ? 'badge-high' : 'badge-low')}`;

    }

    if (bar) {

        bar.style.width = `${Math.min(100, Math.max(0, (ent / 8.0) * 100))}%`;

        bar.style.background = ent >= 7.2 ? 'var(--sev-crit)' : (ent >= 6.5 ? '#f59e0b' : '#10b981');

    }

    if (expl) {

        if (ent >= 7.2) {

            expl.textContent = `High Shannon entropy (${ent.toFixed(2)}) indicates highly randomized byte frequency, typical of cryptographic payloads, compressed archives, or packed executables.`;

        } else if (ent >= 6.5) {

            expl.textContent = `Elevated Shannon entropy (${ent.toFixed(2)}) indicates mild compression or dense executable machine instructions.`;

        } else {

            expl.textContent = `Normal Shannon entropy (${ent.toFixed(2)}) corresponds to standard uncompressed PE structures and ASCII strings.`;

        }

    }



    const tagsContainer = document.getElementById('pe-modal-sec-perms-tags');

    if (tagsContainer) {

        tagsContainer.innerHTML = `

            <span class="badge ${sec.is_executable ? 'badge-high' : 'badge-rule'}">EXECUTE: ${sec.is_executable ? 'YES' : 'NO'}</span>

            <span class="badge ${sec.is_writable ? 'badge-mod' : 'badge-rule'}">WRITE: ${sec.is_writable ? 'YES' : 'NO'}</span>

            <span class="badge badge-low">READ: YES</span>

        `;

    }



    const flagsEl = document.getElementById('pe-modal-sec-flags');

    if (flagsEl) flagsEl.textContent = sec.characteristics || 'IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE';



    const rwxWarn = document.getElementById('pe-modal-sec-rwx-warning');

    if (rwxWarn) rwxWarn.style.display = sec.is_rwx ? 'block' : 'none';



    modal.style.display = 'flex';

}



function closePeSectionDetailModal() {

    const modal = document.getElementById('pe-section-detail-modal');

    if (modal) modal.style.display = 'none';

}



function copyPeSectionDetails() {

    if (!state.activeInspectedSection) return;

    const s = state.activeInspectedSection;

    const text = `Section: ${s.name}\nVirtual Address: ${s.virtual_address}\nVirtual Size: ${s.virtual_size}\nRaw Size: ${s.raw_size}\nEntropy: ${s.entropy}\nCharacteristics: ${s.characteristics}`;

    navigator.clipboard.writeText(text);

    showSocNotification('Copied', 'Section parameters copied to clipboard.', 'success');

}



function exportPeSectionsCSV() {

    const sections = state.peCurrentSections || [];

    if (sections.length === 0) {

        alert('No sections data available to export.');

        return;

    }

    let csv = 'Section_Name,Virtual_Address,Virtual_Size,Raw_Size,Entropy,Permissions,Status\n';

    sections.forEach(s => {

        csv += `"${s.name}","${s.virtual_address}","${s.virtual_size}","${s.raw_size}","${s.entropy}","${(s.characteristics || '').replace(/"/g, '""')}","${s.entropy_status || 'NORMAL'}"\n`;

    });

    const blob = new Blob([csv], { type: 'text/csv' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = `PE_Sections_${state.activeAnalysisId || 'analysis'}.csv`;

    a.click();

    URL.revokeObjectURL(url);

}



function reloadCurrentPeAnalysis() {

    if (state.activeAnalysisId) {

        loadPeStructureAnalysis(state.activeAnalysisId);

        showSocNotification('Refreshed', 'PE analysis structure reloaded.', 'success');

    }

}





/* --------------------------------------------------------------------------

   2. IMPORTS & WINDOWS APIS FORENSIC WORKSPACE

   -------------------------------------------------------------------------- */



async function loadImportsIntelligence(analysisId, resetFilters) {

    const banner = document.getElementById('imports-no-analysis-banner');

    const container = document.getElementById('imports-content-container');

    const tbody = document.getElementById('imports-tbody');



    const targetId = await resolveTargetAnalysisId(analysisId);

    if (!targetId) {

        if (banner) banner.style.display = 'block';

        if (container) container.style.display = 'none';

        return;

    }



    state.activeAnalysisId = targetId;

    if (banner) banner.style.display = 'none';

    if (container) container.style.display = 'block';

    if (tbody) tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">Loading imported APIs for ${escapeHtml(targetId)}...</td></tr>`;



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(targetId)}/imports?limit=1000`);

        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch imports`);

        const data = await res.json();



        state.activeImportsData = data;

        state.importsAllItems = data.imports || [];



        // Update Ribbon

        const fnEl = document.getElementById('imports-active-filename');

        if (fnEl) fnEl.textContent = data.filename || 'sample.exe';

        const anlIdEl = document.getElementById('imports-active-analysis-id');

        if (anlIdEl) anlIdEl.textContent = data.analysis_id || targetId;

        const shaEl = document.getElementById('imports-active-sha256');

        if (shaEl) shaEl.textContent = data.sha256 || 'N/A';

        const totEl = document.getElementById('imports-active-total-counter');

        if (totEl) totEl.textContent = data.total_imports || state.importsAllItems.length;



        // Update Metrics Cards

        const stats = data.statistics || {};

        const stTot = document.getElementById('stat-imports-total');

        if (stTot) stTot.textContent = stats.total_apis || state.importsAllItems.length;

        const stDlls = document.getElementById('stat-imports-dlls');

        if (stDlls) stDlls.textContent = stats.unique_dlls || 0;

        const stSusp = document.getElementById('stat-imports-suspicious');

        if (stSusp) stSusp.textContent = stats.suspicious_apis || 0;

        const stCats = document.getElementById('stat-imports-categories');

        if (stCats) stCats.textContent = Object.keys(stats.categories || {}).length;



        // Update Category Quick Pills Counts

        const catMap = stats.categories || {};

        const pAll = document.getElementById('pill-import-all-count');

        if (pAll) pAll.textContent = state.importsAllItems.length;

        const pSusp = document.getElementById('pill-import-susp-count');

        if (pSusp) pSusp.textContent = stats.suspicious_apis || 0;

        const pProc = document.getElementById('pill-import-proc-count');

        if (pProc) pProc.textContent = catMap['PROCESS'] || 0;

        const pMem = document.getElementById('pill-import-mem-count');

        if (pMem) pMem.textContent = catMap['MEMORY'] || 0;

        const pNet = document.getElementById('pill-import-net-count');

        if (pNet) pNet.textContent = catMap['NETWORK'] || 0;

        const pReg = document.getElementById('pill-import-reg-count');

        if (pReg) pReg.textContent = catMap['REGISTRY'] || 0;

        const pCryp = document.getElementById('pill-import-crypto-count');

        if (pCryp) pCryp.textContent = catMap['CRYPTO'] || 0;



        if (resetFilters) {

            clearImportsFilters(false);

        } else {

            filterAndRenderImports();

        }

    } catch (err) {

        if (tbody) tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell" style="color: var(--sev-high);">Failed to load imports: ${escapeHtml(err.message)}</td></tr>`;

    }

}



function applyImportQuickFilter(category) {

    state.importsActiveQuickFilter = category;



    // Update pill highlight

    document.querySelectorAll('.quick-import-pill').forEach(btn => btn.classList.remove('active'));

    const mapPill = {

        'ALL': 'import-pill-all',

        'SUSPICIOUS': 'import-pill-susp',

        'PROCESS': 'import-pill-proc',

        'MEMORY': 'import-pill-mem',

        'NETWORK': 'import-pill-net',

        'REGISTRY': 'import-pill-reg',

        'CRYPTO': 'import-pill-crypto',

    };

    const pill = document.getElementById(mapPill[category] || 'import-pill-all');

    if (pill) pill.classList.add('active');



    const suspCheck = document.getElementById('imports-filter-suspicious');

    const catSelect = document.getElementById('imports-filter-category');



    if (category === 'SUSPICIOUS') {

        if (suspCheck) suspCheck.checked = true;

        if (catSelect) catSelect.value = 'ALL';

    } else {

        if (suspCheck) suspCheck.checked = false;

        if (catSelect) catSelect.value = category;

    }



    state.importsCurrentPage = 1;

    filterAndRenderImports();

}



function onImportsFilterChange() {

    state.importsCurrentPage = 1;

    filterAndRenderImports();

}



function clearImportsFilters(rerender = true) {

    const sInput = document.getElementById('imports-search-input');

    if (sInput) sInput.value = '';

    const catSelect = document.getElementById('imports-filter-category');

    if (catSelect) catSelect.value = 'ALL';

    const riskSelect = document.getElementById('imports-filter-risk');

    if (riskSelect) riskSelect.value = 'ALL';

    const suspCheck = document.getElementById('imports-filter-suspicious');

    if (suspCheck) suspCheck.checked = false;

    const sortSelect = document.getElementById('imports-sort-by');

    if (sortSelect) sortSelect.value = 'risk';



    document.querySelectorAll('.quick-import-pill').forEach(btn => btn.classList.remove('active'));

    const allPill = document.getElementById('import-pill-all');

    if (allPill) allPill.classList.add('active');



    state.importsCurrentPage = 1;

    if (rerender) filterAndRenderImports();

}



function filterAndRenderImports() {

    const all = state.importsAllItems || [];

    const term = (document.getElementById('imports-search-input')?.value || '').toLowerCase().trim();

    const cat = (document.getElementById('imports-filter-category')?.value || 'ALL').toUpperCase();

    const risk = (document.getElementById('imports-filter-risk')?.value || 'ALL').toUpperCase();

    const suspOnly = document.getElementById('imports-filter-suspicious')?.checked || false;

    const sortBy = document.getElementById('imports-sort-by')?.value || 'risk';



    let filtered = all.filter(item => {

        if (suspOnly && !item.is_suspicious) return false;

        if (cat !== 'ALL' && (item.category || '').toUpperCase() !== cat) return false;

        if (risk !== 'ALL' && (item.risk_relevance || '').toUpperCase() !== risk) return false;

        if (term) {

            const apiMatch = (item.api || '').toLowerCase().includes(term);

            const dllMatch = (item.dll || '').toLowerCase().includes(term);

            const descMatch = (item.description || '').toLowerCase().includes(term);

            if (!apiMatch && !dllMatch && !descMatch) return false;

        }

        return true;

    });



    // Sorting

    const riskWeights = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };

    if (sortBy === 'risk') {

        filtered.sort((a, b) => (riskWeights[(b.risk_relevance || 'LOW').toUpperCase()] || 0) - (riskWeights[(a.risk_relevance || 'LOW').toUpperCase()] || 0));

    } else if (sortBy === 'api_asc') {

        filtered.sort((a, b) => (a.api || '').localeCompare(b.api || ''));

    } else if (sortBy === 'dll_asc') {

        filtered.sort((a, b) => (a.dll || '').localeCompare(b.dll || ''));

    } else if (sortBy === 'category') {

        filtered.sort((a, b) => (a.category || '').localeCompare(b.category || ''));

    }



    state.importsFiltered = filtered;

    state.importsPageSize = parseInt(document.getElementById('imports-page-size-select')?.value || '50', 10);

    state.importsTotalPages = Math.max(1, Math.ceil(filtered.length / state.importsPageSize));

    if (state.importsCurrentPage > state.importsTotalPages) state.importsCurrentPage = state.importsTotalPages;



    const countLabel = document.getElementById('imports-filter-match-count');

    if (countLabel) countLabel.textContent = `Showing ${filtered.length} of ${all.length} functions`;



    renderImportsTableSlice();

}



function renderImportsTableSlice() {

    const tbody = document.getElementById('imports-tbody');

    if (!tbody) return;



    const filtered = state.importsFiltered || [];

    if (filtered.length === 0) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="7" class="empty-state-cell">No imported APIs match your filter criteria.</td></tr>`;

        updateImportsPaginationBar(0, 0, 0);

        return;

    }



    const start = (state.importsCurrentPage - 1) * state.importsPageSize;

    const end = Math.min(start + state.importsPageSize, filtered.length);

    const slice = filtered.slice(start, end);



    tbody.innerHTML = slice.map((imp, idx) => {

        const globalIdx = start + idx + 1;

        const risk = (imp.risk_relevance || 'LOW').toUpperCase();

        const badgeClass = risk === 'CRITICAL' ? 'badge-crit' : (risk === 'HIGH' ? 'badge-high' : (risk === 'MEDIUM' ? 'badge-mod' : 'badge-low'));



        return `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td style="text-align: center; color: var(--text-muted); font-size: 11px;">${globalIdx}</td>

                <td><span class="badge ${badgeClass}">${risk}</span></td>

                <td>

                    <code style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan); cursor: pointer;" onclick="openImportApiDetailModal(${start + idx})" title="Click to inspect API capability">

                        ${escapeHtml(imp.api || 'UnknownAPI')}

                    </code>

                </td>

                <td><code style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${escapeHtml(imp.dll || 'KERNEL32.DLL')}</code></td>

                <td><span style="font-size: 11px; font-weight: 600; color: #a855f7;">${escapeHtml(imp.category || 'GENERAL')}</span></td>

                <td style="font-size: 11px; color: var(--text-secondary); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">

                    ${escapeHtml(imp.description || `Windows API in category ${imp.category || 'GENERAL'}`)}

                </td>

                <td style="text-align: center; white-space: nowrap;">

                    <button class="btn-icon-copy" onclick="navigator.clipboard.writeText('${escapeJsString(imp.api)}'); showSocNotification('Copied', 'API name copied', 'success');" title="Copy API Name">­ƒôï</button>

                    <button class="btn-secondary" onclick="openImportApiDetailModal(${start + idx})" style="font-size: 10px; padding: 2px 6px;" title="Inspect API">­ƒöì</button>

                </td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);



    updateImportsPaginationBar(start + 1, end, filtered.length);

}



function updateImportsPaginationBar(start, end, total) {

    const summary = document.getElementById('imports-pagination-summary');

    if (summary) summary.textContent = `Showing ${start}-${end} of ${total} functions`;



    const btnPrev = document.getElementById('btn-imports-prev');

    const btnNext = document.getElementById('btn-imports-next');

    const btnFirst = document.getElementById('btn-imports-first');

    const btnLast = document.getElementById('btn-imports-last');



    if (btnPrev) btnPrev.disabled = state.importsCurrentPage <= 1;

    if (btnFirst) btnFirst.disabled = state.importsCurrentPage <= 1;

    if (btnNext) btnNext.disabled = state.importsCurrentPage >= state.importsTotalPages;

    if (btnLast) btnLast.disabled = state.importsCurrentPage >= state.importsTotalPages;



    const pageBox = document.getElementById('imports-page-numbers');

    if (pageBox) {

        let pagesHtml = '';

        const cur = state.importsCurrentPage;

        const tot = state.importsTotalPages;

        const maxButtons = 5;

        let startPage = Math.max(1, cur - 2);

        let endPage = Math.min(tot, startPage + maxButtons - 1);

        if (endPage - startPage < maxButtons - 1) {

            startPage = Math.max(1, endPage - maxButtons + 1);

        }



        for (let p = startPage; p <= endPage; p++) {

            pagesHtml += `

                <button class="btn-${p === cur ? 'primary' : 'secondary'}" onclick="goToImportsPage(${p})" style="font-size: 11px; padding: 2px 8px;">

                    ${p}

                </button>

            `;

        }

        pageBox.innerHTML = pagesHtml;

    }

}



function goToImportsPage(page) {

    if (page < 1 || page > state.importsTotalPages) return;

    state.importsCurrentPage = page;

    renderImportsTableSlice();

}



function onImportsPageSizeChange() {

    state.importsCurrentPage = 1;

    filterAndRenderImports();

}



function openImportApiDetailModal(idx) {

    const imp = (state.importsFiltered || [])[idx];

    if (!imp) return;



    state.activeInspectedImport = imp;

    const modal = document.getElementById('import-api-detail-modal');

    if (!modal) return;



    document.getElementById('import-modal-api-name').textContent = imp.api || '-';

    document.getElementById('import-modal-dll-name').textContent = imp.dll || '-';

    document.getElementById('import-modal-category').textContent = imp.category || 'GENERAL';



    const risk = (imp.risk_relevance || 'LOW').toUpperCase();

    const badgeEl = document.getElementById('import-modal-risk-badge');

    if (badgeEl) {

        const badgeClass = risk === 'CRITICAL' ? 'badge-crit' : (risk === 'HIGH' ? 'badge-high' : (risk === 'MEDIUM' ? 'badge-mod' : 'badge-low'));

        badgeEl.innerHTML = `<span class="badge ${badgeClass}">${risk}</span>`;

    }



    const descEl = document.getElementById('import-modal-desc');

    if (descEl) descEl.textContent = imp.description || `Windows API function belonging to category '${imp.category || 'GENERAL'}'. Exported by ${imp.dll || 'system library'}.`;



    const aiResp = document.getElementById('import-modal-ai-response');

    if (aiResp) { aiResp.style.display = 'none'; aiResp.textContent = ''; }



    modal.style.display = 'flex';

}



function closeImportApiDetailModal() {

    const modal = document.getElementById('import-api-detail-modal');

    if (modal) modal.style.display = 'none';

}



function copyImportApiName() {

    if (!state.activeInspectedImport) return;

    navigator.clipboard.writeText(state.activeInspectedImport.api || '');

    showSocNotification('Copied', 'API function name copied', 'success');

}



async function askAiAboutCurrentApi() {

    if (!state.activeInspectedImport || !state.activeAnalysisId) return;

    const imp = state.activeInspectedImport;

    const aiResp = document.getElementById('import-modal-ai-response');

    if (aiResp) {

        aiResp.style.display = 'block';

        aiResp.textContent = 'Consulting AI Security Analyst on this API...';

    }



    try {

        const question = `Explain the security relevance of the Windows API function '${imp.api}' imported from '${imp.dll}' in category '${imp.category}'. How do adversaries commonly abuse this API and what are legitimate benign use cases?`;

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(state.activeAnalysisId)}/ask-ai`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ question, language: state.currentLanguage || 'en' })

        });

        if (!res.ok) throw new Error('AI analysis service unavailable');

        const data = await res.json();

        if (aiResp) aiResp.textContent = data.response || 'No AI interpretation received.';

    } catch (err) {

        if (aiResp) aiResp.textContent = `AI Consultation Error: ${err.message}`;

    }

}



function exportImportsCSV() {

    const items = state.importsFiltered || state.importsAllItems || [];

    if (items.length === 0) {

        alert('No imports to export.');

        return;

    }

    let csv = 'API_Function,DLL_Module,Category,Risk_Relevance,Description\n';

    items.forEach(i => {

        csv += `"${i.api}","${i.dll}","${i.category || 'GENERAL'}","${i.risk_relevance || 'LOW'}","${(i.description || '').replace(/"/g, '""')}"\n`;

    });

    const blob = new Blob([csv], { type: 'text/csv' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = `Imports_${state.activeAnalysisId || 'analysis'}.csv`;

    a.click();

    URL.revokeObjectURL(url);

}



function exportImportsJSON() {

    const items = state.importsFiltered || state.importsAllItems || [];

    const blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = `Imports_${state.activeAnalysisId || 'analysis'}.json`;

    a.click();

    URL.revokeObjectURL(url);

}



function reloadCurrentImports() {

    if (state.activeAnalysisId) {

        loadImportsIntelligence(state.activeAnalysisId, false);

        showSocNotification('Refreshed', 'Imports and APIs reloaded.', 'success');

    }

}





/* --------------------------------------------------------------------------

   3. SUSPICIOUS INDICATORS & THREAT INTELLIGENCE WORKSPACE

   -------------------------------------------------------------------------- */



async function loadIndicatorsAndIocs(analysisId) {

    const banner = document.getElementById('indicators-no-analysis-banner');

    const container = document.getElementById('indicators-content-container');

    const iocTbody = document.getElementById('iocs-tbody');



    const targetId = await resolveTargetAnalysisId(analysisId);

    if (!targetId) {

        if (banner) banner.style.display = 'block';

        if (container) container.style.display = 'none';

        return;

    }



    state.activeAnalysisId = targetId;

    if (banner) banner.style.display = 'none';

    if (container) container.style.display = 'block';

    if (iocTbody) iocTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="6" class="empty-state-cell">Loading IOCs and threat indicators for ${escapeHtml(targetId)}...</td></tr>`;



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(targetId)}/iocs`);

        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch indicators`);

        const data = await res.json();



        state.activeIndicatorsData = data;

        state.indicatorsAllIocs = data.iocs || [];

        state.indicatorsAllIndicators = data.indicators || [];

        state.indicatorsAllYara = data.yara_matches || [];



        // Ribbon

        const fnEl = document.getElementById('indicators-active-filename');

        if (fnEl) fnEl.textContent = data.filename || 'sample.exe';

        const anlIdEl = document.getElementById('indicators-active-analysis-id');

        if (anlIdEl) anlIdEl.textContent = data.analysis_id || targetId;

        const shaEl = document.getElementById('indicators-active-sha256');

        if (shaEl) shaEl.textContent = data.sha256 || 'N/A';

        const totEl = document.getElementById('indicators-active-total-counter');

        if (totEl) totEl.textContent = data.total_iocs || state.indicatorsAllIocs.length;



        // Metrics

        const stInd = document.getElementById('stat-ioc-indicators-count');

        if (stInd) stInd.textContent = state.indicatorsAllIndicators.length;

        const stTot = document.getElementById('stat-ioc-total-count');

        if (stTot) stTot.textContent = state.indicatorsAllIocs.length;

        const stNet = document.getElementById('stat-ioc-network-count');

        if (stNet) stNet.textContent = (data.statistics?.urls || 0) + (data.statistics?.ips || 0) + (data.statistics?.domains || 0);

        const stYara = document.getElementById('stat-ioc-yara-count');

        if (stYara) stYara.textContent = state.indicatorsAllYara.length;



        // Render Indicators Grid Cards

        renderSuspiciousIndicatorsCards(state.indicatorsAllIndicators);



        // Render IOCs Table

        renderIocsTable(state.indicatorsAllIocs);



        // Render YARA Matches Table

        renderYaraMatchesTable(state.indicatorsAllYara);

    } catch (err) {

        if (iocTbody) iocTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="6" class="empty-state-cell" style="color: var(--sev-high);">Failed to load indicators: ${escapeHtml(err.message)}</td></tr>`;

    }

}



function renderSuspiciousIndicatorsCards(indicators) {

    const container = document.getElementById('indicators-container');

    const badge = document.getElementById('indicators-count-badge');

    if (badge) badge.textContent = `${indicators.length} DETECTED`;

    if (!container) return;



    if (!indicators || indicators.length === 0) {

        container.innerHTML = `<div class="empty-table-msg">No suspicious correlated indicators detected. Baseline evaluation shows clean static features.</div>`;

        return;

    }



    container.innerHTML = indicators.map(ind => {

        const sev = (ind.severity || 'LOW').toUpperCase();

        const sevClass = sev === 'CRITICAL' ? 'badge-crit' : (sev === 'HIGH' ? 'badge-high' : (sev === 'MEDIUM' ? 'badge-mod' : 'badge-low'));



        return `

            <div class="soc-card" style="margin-bottom: 12px; border-left: 3px solid ${sev === 'CRITICAL' ? 'var(--sev-crit)' : (sev === 'HIGH' ? 'var(--sev-high)' : 'var(--accent-cyan)')};">

                <div class="card-head flex-between" style="padding: 10px 14px;">

                    <div style="display: flex; align-items: center; gap: 8px;">

                        <span class="card-icon" style="font-size: 14px;">ÔÜá´©Å</span>

                        <strong style="font-size: 13px; color: var(--text-primary);">${escapeHtml(ind.name || 'Indicator')}</strong>

                    </div>

                    <div style="display: flex; gap: 6px;">

                        <span class="badge badge-rule">${escapeHtml(ind.category || 'GENERAL')}</span>

                        <span class="badge ${sevClass}">${sev}</span>

                    </div>

                </div>

                <div class="card-body" style="padding: 10px 14px; font-size: 12px; color: var(--text-secondary); line-height: 1.5;">

                    ${escapeHtml(ind.evidence || 'Evidence observed in static binary structure.')}

                </div>

            </div>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

}



function renderIocsTable(iocs) {

    const tbody = document.getElementById('iocs-tbody');

    if (!tbody) return;



    if (!iocs || iocs.length === 0) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="6" class="empty-state-cell">No extracted IOC artifacts identified for this sample.</td></tr>`;

        return;

    }



    tbody.innerHTML = iocs.map((ioc, idx) => {

        const iocVal = escapeHtml(ioc.value || '');

        const iocValJs = escapeJsString(ioc.value || '');

        const iocType = escapeHtml((ioc.type || 'ARTIFACT').toUpperCase());

        const confPct = Math.round((ioc.confidence || 1.0) * 100);



        return `

            <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                <td style="text-align: center; color: var(--text-muted); font-size: 11px;">${idx + 1}</td>

                <td><span class="badge badge-rule">${iocType}</span></td>

                <td>

                    <code style="font-family: var(--font-mono); font-size: 12px; color: var(--accent-cyan); word-break: break-all;">

                        ${iocVal}

                    </code>

                </td>

                <td style="font-size: 11px; color: var(--text-secondary);">${escapeHtml(ioc.source || 'STATIC_ANALYSIS')}</td>

                <td style="font-size: 11px;"><span class="badge badge-low">${confPct}%</span></td>

                <td style="text-align: center; white-space: nowrap;">

                    <button class="btn-icon-copy" onclick="navigator.clipboard.writeText('${iocValJs}'); showSocNotification('Copied', 'IOC value copied', 'success');" title="Copy IOC">­ƒôï</button>

                    <button class="btn-secondary" onclick="lookupThreatIntelligence('${iocValJs}')" style="font-size: 10px; padding: 2px 8px; color: var(--accent-cyan);" title="Lookup reputation in threat intelligence providers">

                        ­ƒîÉ Lookup

                    </button>

                </td>

            </tr>

        `;

    }).join('');

    // Event delegation for pagination
    numbersContainer.removeEventListener('click', handleStringsPaginationClick);
    numbersContainer.addEventListener('click', handleStringsPaginationClick);

}



function onIocsFilterChange() {

    const term = (document.getElementById('iocs-search-input')?.value || '').toLowerCase().trim();

    const typeFilter = (document.getElementById('iocs-filter-type')?.value || 'ALL').toUpperCase();

    const all = state.indicatorsAllIocs || [];



    const filtered = all.filter(i => {

        if (typeFilter !== 'ALL' && !(i.type || '').toUpperCase().includes(typeFilter)) return false;

        if (term && !(i.value || '').toLowerCase().includes(term) && !(i.type || '').toLowerCase().includes(term)) return false;

        return true;

    });



    renderIocsTable(filtered);

}



function renderYaraMatchesTable(matches) {

    const tbody = document.getElementById('yara-matches-tbody');

    const badge = document.getElementById('yara-status-badge');

    if (!tbody) return;



    if (!matches || matches.length === 0) {

        tbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="4" class="empty-state-cell">No YARA signatures matched. Static rule scan clean.</td></tr>`;

        if (badge) { badge.textContent = 'YARA: Clean'; badge.className = 'badge badge-low'; }

        return;

    }



    if (badge) { badge.textContent = `${matches.length} MATCHES`; badge.className = 'badge badge-high'; }



    tbody.innerHTML = matches.map(ym => `

        <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

            <td><strong style="color: var(--sev-high); font-size: 12px;">${escapeHtml(ym.rule_name)}</strong></td>

            <td><span class="badge badge-rule">${escapeHtml(ym.namespace || 'default')}</span></td>

            <td style="font-size: 12px; color: var(--text-secondary);">${escapeHtml(ym.description || 'Matched rule pattern')}</td>

            <td><code style="font-size: 11px; color: var(--text-muted);">${escapeHtml(Array.isArray(ym.tags) ? ym.tags.join(', ') : (ym.tags || 'none'))}</code></td>

        </tr>

    `).join('');

}



async function lookupThreatIntelligence(indicator) {

    const modal = document.getElementById('threat-intel-lookup-modal');

    if (!modal) return;



    state.currentThreatIntelIndicator = indicator;

    document.getElementById('threat-intel-modal-indicator').textContent = indicator;

    document.getElementById('threat-intel-modal-type').textContent = 'Querying...';

    document.getElementById('threat-intel-modal-provider').textContent = 'Connecting...';

    document.getElementById('threat-intel-modal-rep-badge').innerHTML = '<span class="badge badge-rule">CHECKING</span>';

    document.getElementById('threat-intel-modal-malicious').textContent = '0';

    document.getElementById('threat-intel-modal-message-box').textContent = 'Executing threat intelligence lookup query...';

    document.getElementById('threat-intel-modal-details-container').style.display = 'none';



    modal.style.display = 'flex';



    try {

        const res = await fetchWithAuth('/api/analyses/threat-intel/lookup', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ indicator })

        });

        if (!res.ok) throw new Error(`HTTP ${res.status}: Threat intelligence query failed`);

        const data = await res.json();



        document.getElementById('threat-intel-modal-type').textContent = data.indicator_type || 'GENERIC';

        document.getElementById('threat-intel-modal-provider').textContent = data.provider || 'Local Heuristics';



        const rep = (data.reputation || 'UNCHECKED').toUpperCase();

        const repClass = rep === 'MALICIOUS' ? 'badge-crit' : (rep === 'SUSPICIOUS' ? 'badge-high' : (rep === 'CLEAN' ? 'badge-low' : 'badge-rule'));

        document.getElementById('threat-intel-modal-rep-badge').innerHTML = `<span class="badge ${repClass}">${rep}</span>`;

        document.getElementById('threat-intel-modal-malicious').textContent = data.malicious_votes || 0;



        const msgBox = document.getElementById('threat-intel-modal-message-box');

        if (msgBox) {

            msgBox.innerHTML = `

                <div>${escapeHtml(data.message || 'Threat intelligence query complete.')}</div>

                ${!data.configured ? '<div style="margin-top: 8px; font-size: 11px; color: var(--text-muted);"><em>Defensive invariant: ETHIO-AI Defender never generates fabricated external reputation scores.</em></div>' : ''}

            `;

        }



        if (data.details && Object.keys(data.details).length > 0) {

            const detBox = document.getElementById('threat-intel-modal-details-container');

            const detJson = document.getElementById('threat-intel-modal-details-json');

            if (detBox && detJson) {

                detBox.style.display = 'block';

                detJson.textContent = JSON.stringify(data.details, null, 2);

            }

        }

    } catch (err) {

        document.getElementById('threat-intel-modal-message-box').textContent = `Lookup Error: ${err.message}`;

    }

}



function closeThreatIntelLookupModal() {

    const modal = document.getElementById('threat-intel-lookup-modal');

    if (modal) modal.style.display = 'none';

}



function copyThreatIntelIndicator() {

    if (!state.currentThreatIntelIndicator) return;

    navigator.clipboard.writeText(state.currentThreatIntelIndicator);

    showSocNotification('Copied', 'Indicator copied to clipboard', 'success');

}



function reloadCurrentIndicators() {

    if (state.activeAnalysisId) {

        loadIndicatorsAndIocs(state.activeAnalysisId);

        showSocNotification('Refreshed', 'Indicators and IOCs reloaded.', 'success');

    }

}





/* --------------------------------------------------------------------------

   4. AI SECURITY ANALYST WORKSPACE

   -------------------------------------------------------------------------- */



async function loadAiAnalystView(analysisId) {

    const banner = document.getElementById('ai-no-analysis-banner');

    const container = document.getElementById('ai-content-container');



    const targetId = await resolveTargetAnalysisId(analysisId);

    if (!targetId) {

        if (banner) banner.style.display = 'block';

        if (container) container.style.display = 'none';

        return;

    }



    state.activeAnalysisId = targetId;

    if (banner) banner.style.display = 'none';

    if (container) container.style.display = 'block';



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(targetId)}/ai?language=${state.currentLanguage || 'en'}`);

        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch AI assessment`);

        const data = await res.json();



        state.activeAiData = data;



        // Ribbon

        const fnEl = document.getElementById('ai-active-filename');

        if (fnEl) fnEl.textContent = data.filename || 'sample.exe';

        const anlIdEl = document.getElementById('ai-active-analysis-id');

        if (anlIdEl) anlIdEl.textContent = data.analysis_id || targetId;

        const shaEl = document.getElementById('ai-active-sha256');

        if (shaEl) shaEl.textContent = data.sha256 || 'N/A';

        const riskEl = document.getElementById('ai-active-risk-score');

        if (riskEl) riskEl.textContent = `${data.risk_score || 0} / 100 (${data.risk_level || 'LOW'})`;



        // Executive Summary

        const aiObj = data.ai_assessment || {};

        const sumEl = document.getElementById('ai-summary-display');

        if (sumEl) sumEl.textContent = aiObj.summary || 'Static binary analysis complete.';

        const confBadge = document.getElementById('ai-confidence-badge');

        if (confBadge) confBadge.textContent = `CONFIDENCE: ${aiObj.confidence || 'HIGH'}`;



        // 3 Structured Blocks

        renderBulletList('ai-key-findings-list', aiObj.key_findings || ['Heuristic static assessment complete.']);

        renderBulletList('ai-benign-list', aiObj.benign_explanations || ['Standard compiler artifacts and administrative utilities.']);

        renderBulletList('ai-recommendations-list', aiObj.recommended_investigation || ['Verify binary against software catalog.']);



        // MITRE ATT&CK Matrix

        const mitreList = data.mitre_attack || [];

        const mitreBadge = document.getElementById('ai-mitre-count-badge');

        if (mitreBadge) mitreBadge.textContent = `${mitreList.length} TECHNIQUES`;



        const mitreTbody = document.getElementById('mitre-attack-tbody');

        if (mitreTbody) {

            if (mitreList.length > 0) {

                mitreTbody.innerHTML = mitreList.map(m => `

                    <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                        <td><code style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">${escapeHtml(m.technique_id)}</code></td>

                        <td><strong>${escapeHtml(m.technique_name || 'Technique')}</strong></td>

                        <td><span class="badge badge-rule">${escapeHtml(m.tactical_category || 'Execution')}</span></td>

                        <td style="font-size: 12px; color: var(--text-secondary);">${escapeHtml(m.evidence || '')}</td>

                        <td><span class="badge badge-low">${escapeHtml(m.confidence || 'HIGH')}</span></td>

                    </tr>

                `).join('');

            } else {

                mitreTbody.innerHTML = `<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}"><td colspan="5" class="empty-state-cell">No MITRE ATT&CK alignments identified.</td></tr>`;

            }

        }

    } catch (err) {

        console.error('AI assessment load failed:', err);

    }

}



function executeAiAnalystQuestion(promptText) {

    const input = document.getElementById('ai-analyst-view-input');

    if (input) input.value = promptText;

    executeAiAnalystViewQuestion();

}



async function executeAiAnalystViewQuestion() {

    const input = document.getElementById('ai-analyst-view-input');

    const question = (input ? input.value : '').trim();

    if (!question || !state.activeAnalysisId) return;



    const respBox = document.getElementById('ai-analyst-view-response-box');

    const respText = document.getElementById('ai-analyst-view-response-text');

    const askBtn = document.getElementById('btn-ai-analyst-ask');



    if (respBox && respText) {

        respBox.style.display = 'block';

        respText.textContent = 'Consulting AI Security Analyst...';

    }

    if (askBtn) askBtn.disabled = true;



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(state.activeAnalysisId)}/ask-ai`, {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ question, language: state.currentLanguage || 'en' })

        });

        if (!res.ok) throw new Error('AI consultation service returned an error');

        const data = await res.json();

        if (respText) respText.textContent = data.response || 'No interpretation provided.';

    } catch (err) {

        if (respText) respText.textContent = `Consultation Error: ${err.message}`;

    } finally {

        if (askBtn) askBtn.disabled = false;

    }

}



function copyAiAnalystResponse() {

    const respText = document.getElementById('ai-analyst-view-response-text');

    if (respText && respText.textContent) {

        navigator.clipboard.writeText(respText.textContent);

        showSocNotification('Copied', 'AI response copied to clipboard', 'success');

    }

}



function reloadCurrentAiAssessment() {

    if (state.activeAnalysisId) {

        loadAiAnalystView(state.activeAnalysisId);

        showSocNotification('Refreshed', 'AI Security Analyst assessment reloaded.', 'success');

    }

}





/* --------------------------------------------------------------------------

   5. SECURITY REPORTS WORKSPACE

   -------------------------------------------------------------------------- */



async function loadReportsView(analysisId) {

    const banner = document.getElementById('reports-no-analysis-banner');

    const container = document.getElementById('reports-content-container');



    const targetId = await resolveTargetAnalysisId(analysisId);

    if (!targetId) {

        if (banner) banner.style.display = 'block';

        if (container) container.style.display = 'none';

        return;

    }



    state.activeAnalysisId = targetId;

    if (banner) banner.style.display = 'none';

    if (container) container.style.display = 'block';



    try {

        const res = await fetchWithAuth(`/api/analyses/${encodeURIComponent(targetId)}`);

        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch report data`);

        const data = await res.json();



        state.activeReportData = data;



        // Ribbon

        const fnEl = document.getElementById('reports-active-filename');

        if (fnEl) fnEl.textContent = data.filename || 'sample.exe';

        const anlIdEl = document.getElementById('reports-active-analysis-id');

        if (anlIdEl) anlIdEl.textContent = data.analysis_id || targetId;

        const shaEl = document.getElementById('reports-active-sha256');

        if (shaEl) shaEl.textContent = (data.hashes && data.hashes.sha256) || 'N/A';

        const riskEl = document.getElementById('reports-active-risk-tier');

        if (riskEl) {

            const ts = data.threat_score || {};

            riskEl.textContent = `${ts.risk_level || 'LOW'} (${ts.score || 0}/100)`;

        }



        // Prepopulate Case ID if available

        const caseInp = document.getElementById('report-meta-case-id');

        if (caseInp && data.case_info && data.case_info.case_id) {

            caseInp.value = data.case_info.case_id;

        }



        renderReportLivePreview();

    } catch (err) {

        console.error('Report load failed:', err);

    }

}



function updateReportLivePreview() {

    renderReportLivePreview();

}



function renderReportLivePreview() {

    const frame = document.getElementById('report-preview-frame');

    if (!frame) return;



    const data = state.activeReportData;

    if (!data) {

        frame.innerHTML = '<div class="empty-state-cell">No analysis loaded for report generation.</div>';

        return;

    }



    const org = document.getElementById('report-meta-org')?.value || 'ETHIO-AI Defender SOC';

    const dept = document.getElementById('report-meta-dept')?.value || 'Malware Analysis Unit';

    const caseId = document.getElementById('report-meta-case-id')?.value || 'CASE-001';

    const analyst = document.getElementById('report-meta-analyst')?.value || 'Lead Security Analyst';

    const classification = document.getElementById('report-meta-class')?.value || 'RESTRICTED';



    const fi = data.file_information || {};

    const hashes = data.hashes || {};

    const ts = data.threat_score || {};

    const ai = data.ai_assessment || {};

    const sections = (data.sections && data.sections.sections) || [];

    const imports = (data.imports && data.imports.imports) || [];

    const indicators = (data.indicators && data.indicators.indicators) || [];



    const riskLevel = ts.risk_level || 'LOW';

    const riskBadgeClass = riskLevel === 'CRITICAL' ? 'badge-crit' : (riskLevel === 'HIGH' ? 'badge-high' : (riskLevel === 'MODERATE' || riskLevel === 'MEDIUM' ? 'badge-mod' : 'badge-low'));



    frame.innerHTML = `

        <div style="border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">

            <div>

                <div style="font-size: 11px; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 1px;">

                    ${escapeHtml(org)} ÔÇó ${escapeHtml(dept)}

                </div>

                <h2 style="font-size: 22px; font-weight: 800; color: #f8fafc; margin: 4px 0;">DEFENSIVE STATIC MALWARE ANALYSIS REPORT</h2>

                <div style="font-size: 12px; color: #94a3b8;">

                    Analysis ID: <code style="color: var(--accent-cyan);">${escapeHtml(data.analysis_id)}</code> ÔÇó Case Ref: <strong>${escapeHtml(caseId)}</strong> ÔÇó Analyst: <strong>${escapeHtml(analyst)}</strong>

                </div>

            </div>

            <div style="text-align: right;">

                <span class="badge ${riskBadgeClass}" style="font-size: 13px; padding: 6px 14px;">${escapeHtml(riskLevel)} (${ts.score || 0}/100)</span>

                <div style="font-size: 10px; font-weight: 700; color: #f97316; margin-top: 6px;">${escapeHtml(classification)}</div>

            </div>

        </div>



        <!-- Metadata Table -->

        <div style="margin-bottom: 20px;">

            <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 8px;">1. File Identification & Cryptographic Hashes</h4>

            <table style="width: 100%; border-collapse: collapse; font-size: 12px; background: rgba(255,255,255,0.02); border-radius: 4px;">

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td style="padding: 6px 10px; color: #94a3b8; width: 140px;">Filename:</td>

                    <td style="padding: 6px 10px; font-weight: 700; color: #f8fafc;">${escapeHtml(fi.filename || data.filename)}</td>

                    <td style="padding: 6px 10px; color: #94a3b8; width: 140px;">File Size:</td>

                    <td style="padding: 6px 10px; color: #f8fafc;">${escapeHtml(String(fi.file_size || 0))} bytes</td>

                </tr>

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td style="padding: 6px 10px; color: #94a3b8;">Architecture:</td>

                    <td style="padding: 6px 10px; color: #f8fafc;">${escapeHtml(fi.machine_type || 'x86_64')}</td>

                    <td style="padding: 6px 10px; color: #94a3b8;">File Format:</td>

                    <td style="padding: 6px 10px; color: #f8fafc;">${escapeHtml(fi.file_kind || 'PE32+ Executable')}</td>

                </tr>

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td style="padding: 6px 10px; color: #94a3b8;">SHA-256:</td>

                    <td colspan="3" style="padding: 6px 10px; font-family: monospace; color: var(--accent-cyan);">${escapeHtml(hashes.sha256 || 'N/A')}</td>

                </tr>

                <tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">

                    <td style="padding: 6px 10px; color: #94a3b8;">MD5:</td>

                    <td colspan="3" style="padding: 6px 10px; font-family: monospace; color: #94a3b8;">${escapeHtml(hashes.md5 || 'N/A')}</td>

                </tr>

            </table>

        </div>



        <!-- AI Executive Assessment -->

        <div style="margin-bottom: 20px; background: rgba(0,240,255,0.03); border: 1px solid rgba(0,240,255,0.15); border-radius: 6px; padding: 14px;">

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">

                <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-cyan); margin: 0;">2. Grounded AI Security Executive Assessment</h4>

                <span class="badge badge-rule">Confidence: ${escapeHtml(ai.confidence || 'HIGH')}</span>

            </div>

            <p style="font-size: 13px; line-height: 1.6; color: #f8fafc; margin: 0 0 10px 0;">${escapeHtml(ai.summary || 'Static binary analysis complete.')}</p>

        </div>



        <!-- Correlated Indicators -->

        <div style="margin-bottom: 20px;">

            <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 8px;">3. Correlated Threat Indicators (${indicators.length})</h4>

            ${indicators.length > 0 ? `

                <table style="width: 100%; border-collapse: collapse; font-size: 12px;">

                    <thead><tr style="border-bottom: 1px solid #334155; text-align: left; color: #94a3b8;"><th style="padding: 6px;">Indicator Name</th><th style="padding: 6px;">Category</th><th style="padding: 6px;">Severity</th><th style="padding: 6px;">Technical Evidence</th></tr></thead>

                    <tbody>

                        ${indicators.map(ind => `

                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">

                                <td style="padding: 6px; font-weight: 700; color: #f8fafc;">${escapeHtml(ind.name)}</td>

                                <td style="padding: 6px; color: #a855f7;">${escapeHtml(ind.category)}</td>

                                <td style="padding: 6px;"><span class="badge ${ind.severity === 'CRITICAL' ? 'badge-crit' : (ind.severity === 'HIGH' ? 'badge-high' : 'badge-low')}">${escapeHtml(ind.severity)}</span></td>

                                <td style="padding: 6px; color: #94a3b8;">${escapeHtml(ind.evidence)}</td>

                            </tr>

                        `).join('')}

                    </tbody>

                </table>

            ` : '<div style="font-size: 12px; color: #94a3b8;">No high-risk threat indicators identified.</div>'}

        </div>



        <!-- PE Memory Sections -->

        <div style="margin-bottom: 20px;">

            <h4 style="font-size: 14px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 8px;">4. PE Memory Sections (${sections.length})</h4>

            <table style="width: 100%; border-collapse: collapse; font-size: 11px;">

                <thead><tr style="border-bottom: 1px solid #334155; text-align: left; color: #94a3b8;"><th style="padding: 6px;">Section</th><th style="padding: 6px;">Virtual Addr</th><th style="padding: 6px;">Virtual Size</th><th style="padding: 6px;">Raw Size</th><th style="padding: 6px;">Shannon Entropy</th><th style="padding: 6px;">Permissions</th></tr></thead>

                <tbody>

                    ${sections.map(s => `

                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">

                            <td style="padding: 6px; font-family: monospace; color: var(--accent-cyan); font-weight: 700;">${escapeHtml(s.name)}</td>

                            <td style="padding: 6px; font-family: monospace;">${escapeHtml(String(s.virtual_address))}</td>

                            <td style="padding: 6px;">${escapeHtml(String(s.virtual_size))} bytes</td>

                            <td style="padding: 6px;">${escapeHtml(String(s.raw_size))} bytes</td>

                            <td style="padding: 6px; font-family: monospace;">${(s.entropy || 0).toFixed(2)}</td>

                            <td style="padding: 6px; color: #94a3b8;">${escapeHtml(s.characteristics || '')}</td>

                        </tr>

                    `).join('')}

                </tbody>

            </table>

        </div>



        <!-- Scientific Guarantee Footer -->

        <div style="border-top: 1px solid #334155; padding-top: 14px; margin-top: 24px; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;">

            <div>

                <strong>Zero-Execution Guarantee:</strong> This investigation was performed exclusively via static reverse-engineering. The target binary was never executed.

            </div>

            <div>

                Generated by <strong>ETHIO-AI Defender</strong> ÔÇó Platform v0.1.0

            </div>

        </div>

    `;

}



async function exportCurrentReport(format) {

    if (!state.activeAnalysisId) {

        alert('Please select an active analysis before exporting.');

        return;

    }



    try {

        const url = `/api/analyses/${encodeURIComponent(state.activeAnalysisId)}/report?format=${format}&language=${state.currentLanguage || 'en'}`;

        const res = await fetchWithAuth(url);

        if (!res.ok) throw new Error('Report generation failed');



        if (format === 'html') {

            const htmlContent = await res.text();

            const blob = new Blob([htmlContent], { type: 'text/html' });

            downloadBlob(blob, `Security_Report_${state.activeAnalysisId}.html`);

        } else if (format === 'json') {

            const jsonData = await res.json();

            const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });

            downloadBlob(blob, `Security_Report_${state.activeAnalysisId}.json`);

        } else if (format === 'text' || format === 'txt') {

            const txtContent = await res.text();

            const blob = new Blob([txtContent], { type: 'text/plain' });

            downloadBlob(blob, `Security_Report_${state.activeAnalysisId}.txt`);

        }

        showSocNotification('Export Success', `Exported ${format.toUpperCase()} report`, 'success');

    } catch (err) {

        alert(`Export failed: ${err.message}`);

    }

}



function downloadBlob(blob, filename) {

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.style.display = 'none';

    a.href = url;

    a.download = filename;

    document.body.appendChild(a);

    a.click();

    URL.revokeObjectURL(url);

    document.body.removeChild(a);

}







