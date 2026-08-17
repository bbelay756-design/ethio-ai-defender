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
        nav_home: "መነሻ (Home)",
        nav_analysis: "የትንተና አጠቃላይ እይታ",
        nav_pe: "የ PE ትንተና",
        nav_imports: "የተጠሩ APIs እና DLLs",
        nav_strings: "ጽሁፎች (Strings)",
        nav_indicators: "የስጋት አመልካቾች",
        nav_ai: "የ AI ደህንነት ተንታኝ",
        nav_learning: "የሳይበር ደህንነት ትምህርት",
        nav_admin: "የአስተዳዳሪ እና የተጠቃሚዎች ማዕከል",
        btn_signin: "ግባ (Sign In)",
        tab_signin: "ግባ",
        tab_register: "ተመዝገብ",
        lbl_username: "የተጠቃሚ ስም",
        lbl_email: "ኢሜይል",
        lbl_password: "የይለፍ ቃል",
        lbl_desired_role: "ሚና",
        btn_login_submit: "ግባ",
        btn_register_submit: "መለያ ፍጠር",
        admin_title: "የተጠቃሚዎች አስተዳደር እና የፈቃድ ቁጥጥር",
        admin_subtitle: "የተጠቃሚዎችን ሚናዎች እና የፍቃድ ደረጃዎች መቆጣጠሪያ።",
        btn_refresh_users: "ዝርዝሩን አድስ",
        registered_users_table: "የተመዘገቡ የመድረኩ ተጠቃሚዎች",
        engine_status: "የ Static ሞተር፡ ዝግጁ ነው",
        non_exec_guarantee: "ፋይሉ ሳይሰራ የመመርመር ዋስትና ተረጋግጧል",
        home_title: "ኢትዮ-አይአይ ደህንነት (ETHIO-AI Defender)",
        home_description: "የሀገራዊ የሳይበር ደህንነትን ለማጠናከር እና የተጠቃሚዎችን መረጃ ለመጠበቅ የተሰራ የ PE ፋይሎች static መመርመሪያ እና የ Reverse Engineering ስርዓት።",
        upload_heading: "ፋይል ለ Static ትንተና ያስገቡ",
        dropzone_title: "የ Windows PE ፋይል እዚህ ይጎትቱ እና ይልቀቁ",
        dropzone_subtitle: "ወይም ከኮምፒውተርዎ ለመምረጥ ይጫኑ",
        btn_choose_file: "የ .exe / .dll ፋይል ይምረጡ",
        or_try_demo: "ወይም ዝግጁ የሙከራ ናሙና ይጠቀሙ፡",
        btn_load_demo: "የሙከራ የባንክ ወኪል ፋይል ጫን",
        security_heading: "የደህንነት እና የጥበቃ ፖሊሲ",
        warning_title: "ፋይልን ያለማስኬድ ጥብቅ ፖሊሲ",
        warning_body: "የገቡ ፋይሎች ሳይከፈቱ እና ወደ ስራ ሳይገቡ በ static ትንተና ብቻ ይመረመራሉ። ማናቸውንም አጠራጣሪ ፋይሎች በዋናው ኮምፒውተር ላይ ፈጽሞ እንዳይከፍቱ።",
        supported_formats: "የሚደገፉ የፋይል አይነቶች፡",
        max_size: "ከፍተኛ የፋይል መጠን፡",
        analysis_scope: "የትንተናው ወሰን፡",
        analysis_overview_title: "የትንተና አጠቃላይ እይታ እና የስጋት ደረጃ",
        analysis_overview_subtitle: "የፋይሉ የሃሽ ማንነት፣ አርክቴክቸር እና የ Heuristic ስጋት ውጤት።",
        lbl_filename: "የፋይል ስም",
        lbl_arch: "አርክቴክቸር",
        lbl_risk_level: "የስጋት ደረጃ",
        lbl_threat_score: "የስጋት ውጤት",
        heuristic_metric: "የትንተና ድጋፍ ሰጪ መረጃ",
        lbl_crypto_hashes: "የክሪፕቶግራፊክ ሃሾች",
        lbl_ethio_context: "የኢትዮጵያ ተቋማት ደህንነት ግምገማ",
        lbl_environment: "ዒላማ ተቋም፡",
        lbl_relevance: "የደህንነት ቅድሚያ፡",
        lbl_context_reason: "የግምገማ ምክንያት፡",
        pe_analysis_title: "የ Portable Executable (PE) መዋቅር",
        pe_analysis_subtitle: "የ DOS headers፣ Optional headers፣ የመግቢያ አድራሻ እና የ Sections አደረጃጀት።",
        lbl_pe_headers: "የ PE Headers መረጃዎች",
        lbl_entropy_summary: "የ Entropy እና Anomaly ማጠቃለያ",
        lbl_sections_table: "የ PE Memory Sections ሰንጠረዥ",
        msg_no_sections: "ምንም የ Section መረጃ የለም።",
        imports_title: "የተጠሩ Windows APIs እና DLLs",
        imports_subtitle: "የተመደቡ የውጭ ፈንክሽኖች እና የፋይሉ ቴክኒካዊ ችሎታዎች።",
        msg_no_imports: "ምንም የተጠራ API አልተገኘም።",
        strings_title: "በፋይሉ ውስጥ የተገኙ ጽሁፎች",
        strings_subtitle: "የተመደቡ ASCII እና Unicode ጽሁፎች (URLs, IPs, Registry, Commands)።",
        indicators_title: "የተዛመዱ የስጋት አመልካቾች",
        indicators_subtitle: "በ headers፣ sections እና APIs መካከል የተዛመዱ የደህንነት አመልካቾች።",
        msg_no_indicators: "ለተመረመረው ፋይል ምንም አጠራጣሪ አመልካች አልተገኘም።",
        ai_analyst_title: "የ AI የደህንነት ተንታኝ ግምገማ",
        ai_analyst_subtitle: "የተገኙ static መረጃዎችን በሳይንሳዊ መንገድ የሚያብራራ የ AI ትንተና።",
        ai_summary_head: "የደህንነት ማጠቃለያ",
        ai_key_findings: "ቁልፍ ግኝቶች",
        ai_benign_explanations: "ሊሆኑ የሚችሉ መደበኛ ምክንያቶች",
        ai_recommended_investigation: "የሚመከሩ የክትትል እርምጃዎች",
        learning_title: "የሳይበር ደህንነት Reverse-Engineering ማሰልጠኛ",
        learning_subtitle: "ለተማሪዎች እና ለደህንነት ተመራማሪዎች የተዘጋጁ በይነ-ተግባራዊ ትምህርቶች።",
        select_concept: "ርዕስ ይምረጡ",
        learn_what_is_it: "1. ይህ ምን ማለት ነው?",
        learn_why_it_matters: "2. ለምን ይጠቅማል?",
        learn_explanation: "3. ማብራሪያ",
        learn_does_it_prove_malware: "4. ይህ ብቻውን ቫይረስ መሆኑን ያረጋግጣል?",
        learn_what_next: "5. ቀጥሎ ምን ማጥናት አለብኝ?",
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
            title: "Windows APIs እና VirtualProtect",
            what_is_it: "በ Microsoft Windows የሚሰጡ የስርዓት ጥሪዎች (System Calls) ሲሆኑ የማህደረ-ትውስታ እና የፋይል ስራዎችን ያከናውናሉ።",
            why_it_matters: "የ API ፈንክሽኖችን መመደብ የፋይሉን ቴክኒካዊ ችሎታ በቀላሉ ለመረዳት ያስችላል።",
            beginner: "Windows APIs ፕሮግራሞች ከኮምፒውተሩ ጋር በሰላም እንዲነጋገሩ የተሰሩ ዝግጁ መመሪያዎች ናቸው።",
            advanced: "እንደ VirtualProtect ያሉ APIs የማህደረ-ትውስታ ገጽ ፈቃድን ወደ PAGE_EXECUTE_READWRITE ይቀይራሉ። ይህም ለ JIT compilers ጠቃሚ ሲሆን ለ W+X ጥናትም ይመረመራል።",
            proves: "አያረጋግጥም። ይህ API ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            next: ["ተዛማጅ የ API ጥንዶችን ማጥናት።", "የ Windows Native System Calls አሰራርን መረዳት።"]
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
            title: "የ Portable Executable (PE) ፎርማት",
            what_is_it: "በ Windows ኦፕሬቲንግ ሲስተም ለ Executables (.exe) እና DLLs የሚያገለግል መደበኛ የፋይል መዋቅር ነው።",
            why_it_matters: "Windows ፋይሎችን ወደ ማህደረ-ትውስታ እንዴት እንደሚጭን ይገልጻል።",
            beginner: "PE format ልክ እንደ መጽሐፍ ማውጫ ነው። ለ Windows የትኛው ክፍል ኮድ እንደሆነ ይነግረዋል።",
            advanced: "የ PE መዋቅር ከ DOS MZ header ተነስቶ ወደ IMAGE_NT_HEADERS ይሸጋገራል፤ ይህም ImageBase እና DataDirectory ን ያካትታል።",
            proves: "አያረጋግጥም። ይህ መዋቅር ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            next: ["የ Relative Virtual Address (RVA) ስሌትን መማር።", "የ PE loader አሰራርን መመርመር።"]
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
            title: "የ Shannon Entropy እና የመረጃ እፍጋት",
            what_is_it: "የመረጃን ድብልቅነት እና እፍጋት ከ 0.0 እስከ 8.0 በሚደርስ የሂሳብ ቀመር የሚለካ ስሌት ነው።",
            why_it_matters: "ከፍተኛ Entropy (> 7.2) የታመቀ ወይም የተመሰጠረ ዳታ መኖሩን ያመለክታል።",
            beginner: "Entropy ዳታው ምን ያህል የተዘበራረቀ እንደሆነ ይለካል፤ የተመሰጠሩ ወይም ዚፕ የተደረጉ ፋይሎች ከፍተኛ Entropy አላቸው።",
            advanced: "የ Shannon entropy በአንድ ባይት ውስጥ ያለውን የመረጃ እርግጠኛ-አልባነት ይለካል። በ PE ትንተና packing ን ለመለየት ይረዳል።",
            proves: "አያረጋግጥም። ከፍተኛ Entropy ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።",
            next: ["የእያንዳንዱን section entropy ለይቶ ማስላት።", "በ compression እና encryption መካከል ያለውን ልዩነት መረዳት።"]
        }
    }
};

// Initialization on DOM Loaded
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUploadDropzone();
    initLanguage();
    initAuth();
    renderSelectedConcept();
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
    } else if (tabId === 'learning') {
        if (updateUrl && state.user && state.user.role === 'STUDENT') {
            updateUrlPath('/student/dashboard');
        }
    } else if (['home', 'analysis', 'pe', 'imports', 'strings', 'indicators', 'ai-analyst'].includes(tabId)) {
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

    if (tabId === 'admin') {
        loadUsersList();
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
 * File Upload & Dropzone Handling
 */
function initUploadDropzone() {
    const dropzone = document.getElementById('upload-dropzone');
    const fileInput = document.getElementById('file-upload-input');
    const browseBtn = document.getElementById('btn-browse-file');

    if (!dropzone || !fileInput) return;

    browseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });

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
            uploadFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length > 0) {
            uploadFile(fileInput.files[0]);
        }
    });
}

async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const dropzoneTitle = document.querySelector('.dropzone-title');
    const originalText = dropzoneTitle ? dropzoneTitle.textContent : '';
    if (dropzoneTitle) dropzoneTitle.textContent = `Analyzing ${file.name}... (Zero-Execution Sandbox)`;

    try {
        const response = await fetch(`/api/dashboard/analyze?language=${state.currentLanguage}`, {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Analysis request failed.');
        }

        const data = await response.json();
        state.sampleData = data;
        renderSampleData(data);
        switchTab('analysis');
    } catch (err) {
        alert(`Intake Notice: ${err.message}`);
    } finally {
        if (dropzoneTitle) dropzoneTitle.textContent = originalText;
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

/**
 * Render Sample Data Across All Views
 */
function renderSampleData(data) {
    if (!data) return;

    // Show Sample Badge in Topbar
    const sampleBadge = document.getElementById('current-sample-badge');
    const sampleName = document.getElementById('current-sample-name');
    if (sampleBadge && sampleName) {
        sampleBadge.style.display = 'flex';
        sampleName.textContent = data.filename || 'sample.exe';
    }

    // 1. Overview View
    const fi = data.file_information || {};
    const hashes = data.hashes || {};
    const ts = data.threat_score || { score: 0, risk_level: "LOW" };
    const ec = data.ethiopian_context || {};

    document.getElementById('ov-filename').textContent = fi.filename || data.filename || 'N/A';
    document.getElementById('ov-filetype').textContent = fi.file_kind || 'Windows PE';
    document.getElementById('ov-arch').textContent = fi.machine_type || 'x64';
    document.getElementById('ov-filesize').textContent = `${((fi.file_size || 0) / 1024).toFixed(1)} KB`;
    
    // Risk Level Badge
    const riskLevelEl = document.getElementById('ov-risk-level');
    const levelClass = getRiskBadgeClass(ts.risk_level);
    riskLevelEl.innerHTML = `<span class="badge ${levelClass}">${ts.risk_level}</span>`;

    // Threat Score Gauge
    document.getElementById('ov-score-num').textContent = ts.score || 0;
    const scoreBar = document.getElementById('ov-score-bar');
    if (scoreBar) {
        scoreBar.style.width = `${Math.min(100, Math.max(0, ts.score || 0))}%`;
        scoreBar.style.backgroundColor = getScoreColor(ts.risk_level);
    }

    // Hashes
    document.getElementById('ov-sha256').textContent = hashes.sha256 || 'N/A';
    document.getElementById('ov-sha1').textContent = hashes.sha1 || 'N/A';
    document.getElementById('ov-md5').textContent = hashes.md5 || 'N/A';

    // Ethiopian Context
    document.getElementById('ov-ethio-env').textContent = ec.environment || 'GENERAL';
    const ethioRelEl = document.getElementById('ov-ethio-relevance');
    if (ethioRelEl) {
        ethioRelEl.innerHTML = `<span class="badge ${getRiskBadgeClass(ec.relevance || 'LOW')}">${ec.relevance || 'LOW'}</span>`;
    }
    document.getElementById('ov-ethio-reason').textContent = ec.reason || 'No domestic targeting observed.';

    // 2. PE Analysis View
    const pe = data.pe_information || {};
    const sec = data.sections || { sections: [] };
    const ent = data.entropy || {};

    document.getElementById('pe-subsystem').textContent = pe.subsystem || 'Windows GUI';
    document.getElementById('pe-entry-point').textContent = pe.entry_point || '0x00001000';
    document.getElementById('pe-image-base').textContent = pe.image_base || '0x00400000';
    document.getElementById('pe-compile-time').textContent = pe.compile_time || 'N/A';
    document.getElementById('pe-file-entropy').textContent = `${(ent.file_entropy || 0).toFixed(2)} / 8.0`;
    
    const entClassEl = document.getElementById('pe-entropy-class');
    if (entClassEl) {
        entClassEl.innerHTML = `<span class="badge ${getRiskBadgeClass(ent.classification || 'NORMAL')}">${ent.classification || 'NORMAL'}</span>`;
    }

    document.getElementById('pe-wx-status').textContent = sec.has_wx_sections ? 'DETECTED (W+X Sections Present)' : 'None Detected';
    document.getElementById('pe-total-sections').textContent = sec.total_sections || (sec.sections ? sec.sections.length : 0);

    // Render Sections Table
    const secTbody = document.getElementById('pe-sections-tbody');
    if (secTbody && sec.sections) {
        secTbody.innerHTML = sec.sections.map(s => `
            <tr>
                <td><strong>${escapeHtml(s.name)}</strong></td>
                <td class="font-mono">0x${(s.virtual_address || 0).toString(16).toUpperCase()}</td>
                <td>${s.virtual_size || 0} bytes</td>
                <td>${s.raw_size || 0} bytes</td>
                <td>${(s.entropy || 0).toFixed(2)}</td>
                <td><span class="font-mono">${escapeHtml(s.characteristics || '')}</span></td>
            </tr>
        `).join('');
    }

    // 3. Imports View
    const imp = data.imports || { imports: [] };
    const impTbody = document.getElementById('imports-tbody');
    if (impTbody && imp.imports) {
        impTbody.innerHTML = imp.imports.map(i => `
            <tr>
                <td class="font-mono">${escapeHtml(i.dll)}</td>
                <td><strong>${escapeHtml(i.api)}</strong></td>
                <td><span class="badge badge-rule">${escapeHtml(i.category || 'GENERAL')}</span></td>
                <td><span class="badge ${getRiskBadgeClass(i.risk_relevance || 'LOW')}">${escapeHtml(i.risk_relevance || 'LOW')}</span></td>
            </tr>
        `).join('');
    }

    // 4. Strings View
    const strData = data.strings || {};
    renderStringList('strings-urls-list', 'count-urls', strData.urls);
    renderStringList('strings-ips-list', 'count-ips', strData.ip_addresses);
    renderStringList('strings-regs-list', 'count-regs', strData.registry_paths);
    renderStringList('strings-cmds-list', 'count-cmds', strData.commands);

    // 5. Indicators View
    const indData = data.indicators || { indicators: [] };
    const indContainer = document.getElementById('indicators-container');
    if (indContainer) {
        if (indData.indicators && indData.indicators.length > 0) {
            indContainer.innerHTML = indData.indicators.map(ind => `
                <div class="indicator-card">
                    <div class="indicator-top">
                        <span class="indicator-title">${escapeHtml(ind.name || 'Indicator')}</span>
                        <span class="badge ${getRiskBadgeClass(ind.severity || 'LOW')}">${escapeHtml(ind.severity || 'LOW')}</span>
                    </div>
                    <div class="indicator-evidence"><strong>Evidence:</strong> ${escapeHtml(ind.evidence || '')}</div>
                    <div class="indicator-explanation">${escapeHtml(ind.explanation || '')}</div>
                </div>
            `).join('');
        } else {
            indContainer.innerHTML = `<div class="soc-card"><div class="card-body empty-table-msg">No suspicious indicators detected.</div></div>`;
        }
    }

    // 6. AI Analyst View
    const ai = data.ai_assessment || {};
    document.getElementById('ai-summary-display').textContent = ai.summary || 'No summary generated.';
    document.getElementById('ai-confidence-badge').textContent = `Confidence: ${ai.confidence || 'MEDIUM'}`;

    renderBulletList('ai-key-findings-list', ai.key_findings);
    renderBulletList('ai-benign-list', ai.possible_benign_explanations);
    renderBulletList('ai-recommendations-list', ai.recommended_investigation);
}

function renderStringList(containerId, countId, list) {
    const countEl = document.getElementById(countId);
    const container = document.getElementById(containerId);
    if (!container) return;

    if (countEl) countEl.textContent = list ? list.length : 0;

    if (list && list.length > 0) {
        container.innerHTML = list.map(item => `<li class="string-item">${escapeHtml(item)}</li>`).join('');
    } else {
        container.innerHTML = `<li class="empty-str-item">None found</li>`;
    }
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
 * Learning Center Concept Renderer
 */
function setLearningDifficulty(diff) {
    state.currentDifficulty = diff;
    document.getElementById('diff-beginner').classList.toggle('active', diff === 'BEGINNER');
    document.getElementById('diff-advanced').classList.toggle('active', diff === 'ADVANCED');
    renderSelectedConcept();
}

function renderSelectedConcept() {
    const select = document.getElementById('learning-topic-select');
    const topicKey = select ? select.value : 'WINDOWS_APIS';
    const lang = state.currentLanguage;
    const diff = state.currentDifficulty;

    const concept = (CONCEPTS_DB[topicKey] && CONCEPTS_DB[topicKey][lang]) ? CONCEPTS_DB[topicKey][lang] : CONCEPTS_DB.WINDOWS_APIS.en;

    document.getElementById('lesson-title').textContent = concept.title;
    document.getElementById('lesson-what-is-it').textContent = concept.what_is_it;
    document.getElementById('lesson-why-matters').textContent = concept.why_it_matters;
    
    document.getElementById('lesson-level-badge').textContent = diff === 'BEGINNER' ? 'Beginner' : 'Advanced';
    document.getElementById('lesson-explanation-body').textContent = diff === 'BEGINNER' ? concept.beginner : concept.advanced;
    
    document.getElementById('lesson-proves-malicious').textContent = concept.proves;
    renderBulletList('lesson-next-steps', concept.next);
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
        banner.innerHTML = `<span>⚠️ ${escapeHtml(msg)}</span> <button type="button" onclick="initAuth()" style="margin-left: 8px; background: none; border: 1px solid currentColor; color: inherit; border-radius: 4px; padding: 2px 8px; cursor: pointer; font-size: 11px;">🔄 Retry</button>`;
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
    const navAnalysis = document.getElementById('nav-item-analysis');
    const navPE = document.getElementById('nav-item-pe');
    const navImports = document.getElementById('nav-item-imports');
    const navStrings = document.getElementById('nav-item-strings');
    const navIndicators = document.getElementById('nav-item-indicators');
    const navAI = document.getElementById('nav-item-ai');
    const navLearning = document.getElementById('nav-item-learning');
    const navAdmin = document.getElementById('nav-item-admin');

    // Hide all navigation elements initially
    [navHome, navAnalysis, navPE, navImports, navStrings, navIndicators, navAI, navLearning, navAdmin].forEach(el => {
        if (el) el.style.display = 'none';
    });

    if (!state.user || state.authStatus !== 'AUTHENTICATED') {
        return;
    }

    const role = (state.user.role || '').toUpperCase();
    const isAm = state.currentLanguage === 'am';

    if (role === 'ADMIN') {
        // ADMIN sees: Dashboard, Users, All Analyses, Threat Intelligence, Reports, Audit Logs, Settings
        if (navAdmin) {
            navAdmin.style.display = 'block';
            const label = document.getElementById('nav-label-admin');
            if (label) label.textContent = isAm ? 'የአስተዳዳሪ ማዕከል' : 'Admin & Users';
        }
        if (navAnalysis) {
            navAnalysis.style.display = 'block';
            const label = document.getElementById('nav-label-analysis');
            if (label) label.textContent = isAm ? 'ሁሉም ትንተናዎች' : 'All Analyses';
        }
        if (navIndicators) {
            navIndicators.style.display = 'block';
            const label = document.getElementById('nav-label-indicators');
            if (label) label.textContent = isAm ? 'የስጋት መረጃዎች' : 'Threat Intelligence';
        }
        if (navAI) {
            navAI.style.display = 'block';
            const label = document.getElementById('nav-label-ai');
            if (label) label.textContent = isAm ? 'የደህንነት ሪፖርቶች' : 'Security Reports';
        }
        if (navHome) {
            navHome.style.display = 'block';
            const label = document.getElementById('nav-label-home');
            if (label) label.textContent = isAm ? 'ትንተና ማስጀመሪያ' : 'New Analysis / Intake';
        }
    } else if (role === 'ANALYST') {
        // ANALYST sees: Dashboard, New Analysis, Analysis History, Threat Intelligence, Reports, Learning Center
        if (navHome) {
            navHome.style.display = 'block';
            const label = document.getElementById('nav-label-home');
            if (label) label.textContent = isAm ? 'አዲስ ትንተና' : 'Dashboard / Intake';
        }
        if (navAnalysis) {
            navAnalysis.style.display = 'block';
            const label = document.getElementById('nav-label-analysis');
            if (label) label.textContent = isAm ? 'የትንተና ታሪክ' : 'Analysis History';
        }
        if (navPE) navPE.style.display = 'block';
        if (navImports) navImports.style.display = 'block';
        if (navStrings) navStrings.style.display = 'block';
        if (navIndicators) {
            navIndicators.style.display = 'block';
            const label = document.getElementById('nav-label-indicators');
            if (label) label.textContent = isAm ? 'የስጋት መረጃዎች' : 'Threat Intelligence';
        }
        if (navAI) {
            navAI.style.display = 'block';
            const label = document.getElementById('nav-label-ai');
            if (label) label.textContent = isAm ? 'የደህንነት ሪፖርቶች' : 'Security Reports';
        }
        if (navLearning) {
            navLearning.style.display = 'block';
            const label = document.getElementById('nav-label-learning');
            if (label) label.textContent = isAm ? 'የሳይበር ደህንነት ትምህርት' : 'Learning Center';
        }
    } else if (role === 'STUDENT') {
        // STUDENT sees: Dashboard, Learning Center, Safe Analysis, My Reports
        if (navLearning) {
            navLearning.style.display = 'block';
            const label = document.getElementById('nav-label-learning');
            if (label) label.textContent = isAm ? 'የተማሪዎች መማሪያ' : 'Learning Center';
        }
        if (navHome) {
            navHome.style.display = 'block';
            const label = document.getElementById('nav-label-home');
            if (label) label.textContent = isAm ? 'ደህንነቱ የተጠበቀ ናሙና' : 'Safe Sample Analysis';
        }
        if (navAnalysis) {
            navAnalysis.style.display = 'block';
            const label = document.getElementById('nav-label-analysis');
            if (label) label.textContent = isAm ? 'የእኔ ሪፖርቶች' : 'My Reports';
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
    const role = document.getElementById('reg-role').value;

    if (errBox) errBox.style.display = 'none';
    clearConnectionError();

    try {
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, role })
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
            '/reports': 'ai-analyst',
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
                if (bannerIcon) bannerIcon.textContent = '🛡️';
                if (bannerTitle) bannerTitle.textContent = isAm ? 'የአስተዳዳሪ ማዕከል ገቢር ነው (Administrator Control Active)' : 'Administrator Control Center Active';
                if (bannerDesc) bannerDesc.textContent = isAm ? 'ሙሉ የስርዓት ቁጥጥር: የተጠቃሚዎች ሚና አስተዳደር እና የደህንነት ኦዲት መዝገቦች።' : 'Full platform access: manage users, configure RBAC permissions, and view audit trail logs.';
            } else if (state.user.role === 'ANALYST') {
                roleBanner.classList.add('banner-analyst');
                if (bannerIcon) bannerIcon.textContent = '🔍';
                if (bannerTitle) bannerTitle.textContent = isAm ? 'የ SOC ስጋት ትንተና የስራ ቦታ (SOC Threat Analysis Active)' : 'SOC Threat Analysis Workspace Active';
                if (bannerDesc) bannerDesc.textContent = isAm ? 'የማልዌር ስጋት ትንተና: PE መዋቅር፣ የ entropy ስሌት፣ ጽሁፎች እና የደህንነት ሪፖርት ማመንጨት።' : 'Operational malware triage: static PE inspection, entropy analysis, string extraction, and report generation.';
            } else {
                roleBanner.classList.add('banner-student');
                if (bannerIcon) bannerIcon.textContent = '🎓';
                if (bannerTitle) bannerTitle.textContent = isAm ? 'የተማሪዎች የሳይበር ደህንነት ትምህርት ቤት (Student Lab Active)' : 'Cybersecurity Student Learning Lab Active';
                if (bannerDesc) bannerDesc.textContent = isAm ? 'በይነተገናኝ የ reverse engineering ትምህርቶች፣ የፅንሰ-ሀሳብ ማብራሪያዎች እና የናሙና ልምምዶች።' : 'Interactive educational reverse-engineering lessons, concept breakdowns, and safe sample practice.';
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

async function loadUsersList() {
    if (!state.user || state.user.role !== 'ADMIN') return;
    const tbody = document.getElementById('admin-users-tbody');
    if (!tbody) return;

    try {
        const res = await fetchWithAuth('/api/auth/users');
        if (!res || !res.ok) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state-cell">Access denied or failed to load users.</td></tr>';
            return;
        }
        const users = await res.json();
        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state-cell">No users registered yet.</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(u => `
            <tr>
                <td style="font-family: var(--font-mono); font-weight: 600;">#${u.id}</td>
                <td style="font-weight: 600; color: var(--text-primary);">${escapeHtml(u.username)}</td>
                <td style="color: var(--text-secondary);">${escapeHtml(u.email)}</td>
                <td>
                    <select class="dropdown-select" style="padding: 4px 8px; font-size: 11px; width: auto;" onchange="updateUserRole(${u.id}, this.value)">
                        <option value="STUDENT" ${u.role === 'STUDENT' ? 'selected' : ''}>STUDENT</option>
                        <option value="ANALYST" ${u.role === 'ANALYST' ? 'selected' : ''}>ANALYST</option>
                        <option value="ADMIN" ${u.role === 'ADMIN' ? 'selected' : ''}>ADMIN</option>
                    </select>
                </td>
                <td><span class="badge ${u.is_active ? 'badge-low' : 'badge-crit'}">${u.is_active ? 'ACTIVE' : 'INACTIVE'}</span></td>
                <td>
                    <span style="font-size: 11px; color: var(--text-muted);">${u.permissions ? u.permissions.length : 0} permissions</span>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function updateUserRole(userId, newRole) {
    try {
        const res = await fetchWithAuth(`/api/auth/users/${userId}/role`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: newRole })
        });
        if (!res || !res.ok) {
            const data = await res.json();
            alert('Failed to update role: ' + (data.detail || res.statusText));
            loadUsersList();
            return;
        }
        loadUsersList();
    } catch (err) {
        alert('Error updating role: ' + err.message);
    }
}

/**
 * Security Audit Viewer & SOC Log Management (Module 17)
 */
function switchAdminTab(subtab) {
    const btnUsers = document.getElementById('admin-subtab-users');
    const btnAudit = document.getElementById('admin-subtab-audit');
    const panelUsers = document.getElementById('admin-panel-users');
    const panelAudit = document.getElementById('admin-panel-audit');

    if (subtab === 'users') {
        if (btnUsers) btnUsers.classList.add('active');
        if (btnAudit) btnAudit.classList.remove('active');
        if (panelUsers) panelUsers.style.display = 'block';
        if (panelAudit) panelAudit.style.display = 'none';
        loadUsersList();
    } else {
        if (btnUsers) btnUsers.classList.remove('active');
        if (btnAudit) btnAudit.classList.add('active');
        if (panelUsers) panelUsers.style.display = 'none';
        if (panelAudit) panelAudit.style.display = 'block';
        loadAuditLogs();
    }
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
            if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="empty-state-cell">Access denied or failed to load audit logs.</td></tr>';
            return;
        }

        const data = await logsRes.json();
        if (!data.items || data.items.length === 0) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="empty-state-cell">No matching audit events recorded yet.</td></tr>';
            return;
        }

        if (tbody) {
            tbody.innerHTML = data.items.map(item => {
                const resClass = getAuditResultBadgeClass(item.result);
                const detailsStr = item.details ? JSON.stringify(item.details) : '{}';
                const userDisplay = item.username ? `${escapeHtml(item.username)} (#${item.user_id})` : (item.ip_address || 'System / Anon');

                return `
                    <tr>
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
                        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(detailsStr)}">
                            ${escapeHtml(detailsStr)}
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;
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


