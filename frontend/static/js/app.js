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
    } else if (['home', 'history', 'analysis', 'pe', 'imports', 'strings', 'indicators', 'ai-analyst'].includes(tabId)) {
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
        switchAdminTab(state.adminCurrentSubtab || 'overview');
    } else if (tabId === 'history') {
        loadAnalysisHistory();
    } else if (tabId === 'learning') {
        switchStudentTab(state.studentCurrentSubtab || 'concepts');
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
        { id: 'prog-stage-1', text: '⚡ 1. Uploading payload stream safely...' },
        { id: 'prog-stage-2', text: '🔍 2. Validating DOS header & PE format...' },
        { id: 'prog-stage-3', text: '🔑 3. Calculating SHA-256, SHA-1, MD5 hashes...' },
        { id: 'prog-stage-4', text: '🧩 4. Parsing PE headers, sections & entropy...' },
        { id: 'prog-stage-5', text: '🔌 5. Extracting APIs, strings & threat indicators...' },
        { id: 'prog-stage-6', text: '🤖 6. Running YARA & synthesizing AI assessment...' },
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
    const fi = data.file_information || data.file || {};
    const hashes = data.hashes || {};
    const ts = data.threat_score || data.risk || data.risk_score || { score: 0, risk_level: "LOW" };
    const ec = data.ethiopian_context || {};

    document.getElementById('ov-filename').textContent = fi.filename || data.filename || 'N/A';
    document.getElementById('ov-filetype').textContent = fi.file_kind || 'Windows PE';
    document.getElementById('ov-arch').textContent = fi.machine_type || 'x64';
    document.getElementById('ov-filesize').textContent = `${((fi.file_size || data.size || 0) / 1024).toFixed(1)} KB`;
    
    // Risk Level Badge
    const riskLevelEl = document.getElementById('ov-risk-level');
    const levelClass = getRiskBadgeClass(ts.risk_level);
    riskLevelEl.innerHTML = `<span class="badge ${levelClass}">${ts.risk_level}</span>`;

    // Threat Score Gauge
    document.getElementById('ov-score-num').textContent = ts.score !== undefined ? ts.score : (data.risk_score || 0);
    const scoreBar = document.getElementById('ov-score-bar');
    if (scoreBar) {
        const scoreVal = ts.score !== undefined ? ts.score : (data.risk_score || 0);
        scoreBar.style.width = `${Math.min(100, Math.max(0, scoreVal))}%`;
        scoreBar.style.backgroundColor = getScoreColor(ts.risk_level);
    }

    // Hashes
    document.getElementById('ov-sha256').textContent = hashes.sha256 || data.sha256 || 'N/A';
    document.getElementById('ov-sha1').textContent = hashes.sha1 || data.sha1 || 'N/A';
    document.getElementById('ov-md5').textContent = hashes.md5 || data.md5 || 'N/A';

    // Ethiopian Context
    document.getElementById('ov-ethio-env').textContent = ec.environment || 'GENERAL';
    const ethioRelEl = document.getElementById('ov-ethio-relevance');
    if (ethioRelEl) {
        ethioRelEl.innerHTML = `<span class="badge ${getRiskBadgeClass(ec.relevance || 'LOW')}">${ec.relevance || 'LOW'}</span>`;
    }
    document.getElementById('ov-ethio-reason').textContent = ec.reason || 'No domestic targeting observed.';

    // Risk Factors Breakdown ("Why was this score generated?")
    const rfTbody = document.getElementById('ov-risk-factors-tbody');
    const riskFactors = data.risk_factors || [];
    if (rfTbody) {
        if (riskFactors.length > 0) {
            rfTbody.innerHTML = riskFactors.map(rf => `
                <tr>
                    <td><strong>${escapeHtml(rf.name)}</strong></td>
                    <td><span class="badge badge-rule">${escapeHtml(rf.category || 'GENERAL')}</span></td>
                    <td><span class="badge ${getRiskBadgeClass(rf.severity || 'LOW')}">${escapeHtml(rf.severity || 'LOW')}</span></td>
                    <td class="font-mono" style="color: var(--accent-orange); font-weight: bold;">+${rf.weight} pts</td>
                    <td>${escapeHtml(rf.evidence || '')}</td>
                </tr>
            `).join('');
        } else {
            rfTbody.innerHTML = `<tr><td colspan="5" class="empty-state-cell">No suspicious scoring factors detected. Heuristic base baseline.</td></tr>`;
        }
    }

    // 2. PE Analysis View
    const pe = data.pe_information || data.pe || {};
    const sec = data.sections || { sections: [] };
    const sectionsList = Array.isArray(sec) ? sec : (sec.sections || []);
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

    const hasWx = sec.has_wx_sections || sectionsList.some(s => (s.characteristics || '').includes('EXECUTE') && (s.characteristics || '').includes('WRITE'));
    document.getElementById('pe-wx-status').textContent = hasWx ? 'DETECTED (W+X Sections Present)' : 'None Detected';
    document.getElementById('pe-total-sections').textContent = sectionsList.length;

    // Render Sections Table
    const secTbody = document.getElementById('pe-sections-tbody');
    if (secTbody) {
        if (sectionsList.length > 0) {
            secTbody.innerHTML = sectionsList.map(s => `
                <tr>
                    <td><strong>${escapeHtml(s.name)}</strong></td>
                    <td class="font-mono">${typeof s.virtual_address === 'number' ? '0x' + s.virtual_address.toString(16).toUpperCase() : escapeHtml(s.virtual_address)}</td>
                    <td>${s.virtual_size || 0} bytes</td>
                    <td>${s.raw_size || 0} bytes</td>
                    <td>${Number(s.entropy || 0).toFixed(2)}</td>
                    <td><span class="font-mono">${escapeHtml(s.characteristics || '')}</span></td>
                </tr>
            `).join('');
        } else {
            secTbody.innerHTML = `<tr><td colspan="6" class="empty-state-cell">No sections available.</td></tr>`;
        }
    }

    // 3. Imports View
    const imp = data.imports || { imports: [] };
    const importsList = Array.isArray(imp) ? imp : (imp.imports || []);
    const impTbody = document.getElementById('imports-tbody');
    if (impTbody) {
        if (importsList.length > 0) {
            impTbody.innerHTML = importsList.map(i => `
                <tr>
                    <td class="font-mono">${escapeHtml(i.dll)}</td>
                    <td><strong>${escapeHtml(i.api)}</strong></td>
                    <td><span class="badge badge-rule">${escapeHtml(i.category || 'GENERAL')}</span></td>
                    <td><span class="badge ${getRiskBadgeClass(i.risk_relevance || 'LOW')}">${escapeHtml(i.risk_relevance || 'LOW')}</span></td>
                </tr>
            `).join('');
        } else {
            impTbody.innerHTML = `<tr><td colspan="4" class="empty-table-msg" data-i18n="msg_no_imports">No imported APIs detected.</td></tr>`;
        }
    }

    // 4. Strings View
    const strData = data.strings || {};
    renderStringList('strings-urls-list', 'count-urls', strData.urls);
    renderStringList('strings-ips-list', 'count-ips', strData.ip_addresses);
    renderStringList('strings-regs-list', 'count-regs', strData.registry_paths);
    renderStringList('strings-cmds-list', 'count-cmds', strData.commands);

    // 5. Indicators, IOCs & YARA View
    const indData = data.indicators || { indicators: [] };
    const indicatorsList = Array.isArray(indData) ? indData : (indData.indicators || []);
    const indContainer = document.getElementById('indicators-container');
    if (indContainer) {
        if (indicatorsList.length > 0) {
            indContainer.innerHTML = indicatorsList.map(ind => `
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
            indContainer.innerHTML = `<div class="soc-card"><div class="card-body empty-table-msg">No suspicious indicators detected for the current sample.</div></div>`;
        }
    }

    // Extracted IOCs
    const iocsTbody = document.getElementById('iocs-tbody');
    const iocItems = (data.iocs && data.iocs.items) ? data.iocs.items : (Array.isArray(data.iocs) ? data.iocs : []);
    if (iocsTbody) {
        if (iocItems.length > 0) {
            iocsTbody.innerHTML = iocItems.map(ioc => `
                <tr>
                    <td><span class="badge badge-rule">${escapeHtml(ioc.type)}</span></td>
                    <td class="font-mono" style="word-break: break-all;">${escapeHtml(ioc.value)}</td>
                    <td>${escapeHtml(ioc.source || 'STATIC_ANALYSIS')}</td>
                    <td>${(ioc.confidence * 100).toFixed(0)}%</td>
                </tr>
            `).join('');
        } else {
            iocsTbody.innerHTML = `<tr><td colspan="4" class="empty-state-cell">No indicators of compromise extracted.</td></tr>`;
        }
    }

    // YARA Matches
    const yaraTbody = document.getElementById('yara-matches-tbody');
    const yaraBadge = document.getElementById('yara-status-badge');
    const yaraObj = data.yara_matches || {};
    const yaraMatches = yaraObj.matches || (Array.isArray(yaraObj) ? yaraObj : []);

    if (yaraBadge) {
        if (yaraObj.available === false || yaraObj.status === 'UNAVAILABLE') {
            yaraBadge.className = 'badge badge-low';
            yaraBadge.textContent = 'YARA engine unavailable';
        } else {
            yaraBadge.className = 'badge badge-rule';
            yaraBadge.textContent = `YARA Engine: Operational (${yaraMatches.length} matches)`;
        }
    }

    if (yaraTbody) {
        if (yaraObj.available === false) {
            yaraTbody.innerHTML = `<tr><td colspan="4" class="empty-state-cell" style="color: var(--text-muted);">YARA engine unavailable on host system. Static analysis unaffected.</td></tr>`;
        } else if (yaraMatches.length > 0) {
            yaraTbody.innerHTML = yaraMatches.map(ym => `
                <tr>
                    <td><strong>${escapeHtml(ym.rule_name)}</strong></td>
                    <td>${escapeHtml(ym.namespace || 'default')}</td>
                    <td>${escapeHtml(Array.isArray(ym.tags) ? ym.tags.join(', ') : (ym.tags || 'None'))}</td>
                    <td>${escapeHtml(ym.description || 'Matched rule pattern')}</td>
                </tr>
            `).join('');
        } else {
            yaraTbody.innerHTML = `<tr><td colspan="4" class="empty-state-cell">No YARA rule matches detected in sample.</td></tr>`;
        }
    }

    // 6. AI Analyst View & MITRE ATT&CK
    const ai = data.ai_assessment || {};
    document.getElementById('ai-summary-display').textContent = ai.summary || 'No summary generated.';
    document.getElementById('ai-confidence-badge').textContent = `Confidence: ${ai.confidence || 'MEDIUM'}`;

    renderBulletList('ai-key-findings-list', ai.key_findings);
    renderBulletList('ai-benign-list', ai.possible_benign_explanations);
    renderBulletList('ai-recommendations-list', ai.recommended_investigation);

    // MITRE ATT&CK Matrix
    const mitreTbody = document.getElementById('mitre-attack-tbody');
    const mitreList = data.mitre_attack || [];
    if (mitreTbody) {
        if (mitreList.length > 0) {
            mitreTbody.innerHTML = mitreList.map(m => `
                <tr>
                    <td class="font-mono"><strong>${escapeHtml(m.technique_id)}</strong></td>
                    <td>${escapeHtml(m.technique_name)}</td>
                    <td><span class="badge badge-rule">${escapeHtml(m.tactic)}</span></td>
                    <td>${escapeHtml(m.evidence)}</td>
                    <td><span class="badge ${getRiskBadgeClass(m.confidence || 'MEDIUM')}">${escapeHtml(m.confidence || 'MEDIUM')}</span></td>
                </tr>
            `).join('');
        } else {
            mitreTbody.innerHTML = `<tr><td colspan="5" class="empty-state-cell">No MITRE ATT&CK technique alignments identified.</td></tr>`;
        }
    }
}

/**
 * Export Security Analysis Report in requested format
 */
function exportCurrentReport(format) {
    if (!state.sampleData || !state.sampleData.analysis_id) {
        alert('No analysis sample is currently loaded to export.');
        return;
    }
    const analysisId = state.sampleData.analysis_id;
    const lang = state.currentLanguage || 'en';
    const reportUrl = `/api/analyses/${encodeURIComponent(analysisId)}/report?format=${format}&language=${lang}`;
    window.open(reportUrl, '_blank');
}

/**
 * Load and Render Analysis History
 */
async function loadAnalysisHistory() {
    const tbody = document.getElementById('history-tbody');
    const badge = document.getElementById('history-count-badge');
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell">Loading analysis records from database...</td></tr>`;
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
            tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell" style="color: var(--sev-high);">Error loading history: ${err.message}</td></tr>`;
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
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell">No analysis records match your search filter.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(item => {
        const shortHash = item.sha256 ? `${item.sha256.substring(0, 12)}...` : 'N/A';
        const dateStr = item.created_at ? item.created_at.replace('T', ' ').substring(0, 19) : 'N/A';
        const riskLevel = item.classification || 'LOW';
        const riskBadge = getRiskBadgeClass(riskLevel);
        const score = item.risk_score !== undefined ? item.risk_score : 0;

        return `
            <tr>
                <td class="font-mono"><strong>${escapeHtml(item.analysis_id)}</strong></td>
                <td>
                    <div style="font-weight: 600;">${escapeHtml(item.filename)}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">${((item.size || 0) / 1024).toFixed(1)} KB</div>
                </td>
                <td><span class="badge badge-rule">${escapeHtml(item.file_type || 'EXE')} (${escapeHtml(item.architecture || 'x64')})</span></td>
                <td class="font-mono">
                    <span title="${escapeHtml(item.sha256)}">${shortHash}</span>
                    <button class="btn-icon-copy" onclick="copyTextToClipboard('${escapeHtml(item.sha256)}')" title="Copy full SHA-256">📋</button>
                </td>
                <td>
                    <span class="badge ${riskBadge}">${riskLevel} (${score}/100)</span>
                </td>
                <td style="font-size: 12px; color: var(--text-secondary);">${dateStr}</td>
                <td>
                    <div style="display: flex; gap: 6px; align-items: center;">
                        <button class="btn-primary" style="padding: 4px 8px; font-size: 11px;" onclick="openAnalysisInWorkspace('${escapeHtml(item.analysis_id)}')" title="Load into Workspace">📂 Open</button>
                        <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="window.open('/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}', '_blank')" title="View Report">📄 Report</button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

async function openAnalysisInWorkspace(analysisId) {
    try {
        const response = await fetchWithAuth(`/api/analyses/${encodeURIComponent(analysisId)}?language=${state.currentLanguage}`);
        if (!response.ok) {
            throw new Error('Failed to fetch analysis details from database.');
        }

        const data = await response.json();
        state.sampleData = data;
        renderSampleData(data);
        switchTab('analysis');

    } catch (err) {
        alert(`Could not open analysis: ${err.message}`);
    }
}

function copyTextToClipboard(text) {
    if (!navigator.clipboard) {
        prompt('Copy text:', text);
        return;
    }
    navigator.clipboard.writeText(text).then(() => {
        alert(`Copied to clipboard: ${text}`);
    }).catch(() => {
        prompt('Copy text:', text);
    });
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
 * Cybersecurity Student Learning Lab Controller (Module 12 & 16)
 */
state.studentCurrentSubtab = 'concepts';
state.labActiveResultTab = 'headers';
state.practiceSamplesList = [];
state.quizQuestionsList = [];

function switchStudentTab(subtab) {
    state.studentCurrentSubtab = subtab;
    const tabs = ['concepts', 'labs', 'quizzes', 'anatomy'];

    tabs.forEach(t => {
        const btn = document.getElementById(`student-subtab-${t}`);
        const panel = document.getElementById(`student-panel-${t}`);
        if (btn) btn.classList.toggle('active', t === subtab);
        if (panel) panel.style.display = (t === subtab) ? 'block' : 'none';
    });

    if (subtab === 'concepts') {
        renderSelectedConcept();
    } else if (subtab === 'labs') {
        loadPracticeSamples();
    } else if (subtab === 'quizzes') {
        loadQuizQuestions();
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
                if (anatomySummary) anatomySummary.textContent = `${data.visual_anatomy.structure_name} — ${data.visual_anatomy.summary}`;
                if (anatomyTbody) {
                    anatomyTbody.innerHTML = data.visual_anatomy.fields.map(f => `
                        <tr>
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
            const learningBullets = (s.key_learning_points || []).map(p => `<li style="font-size: 11px; margin-bottom: 4px;">✓ ${escapeHtml(p)}</li>`).join('');
            const expectedPills = (s.expected_findings || []).map(f => `<span class="badge badge-low" style="font-size: 10px; margin: 2px;">🎯 ${escapeHtml(f)}</span>`).join('');

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
                            🔬 Load & Analyze Sample in Lab
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (err) {
        grid.innerHTML = `<div class="empty-state-cell">Error: ${escapeHtml(err.message)}</div>`;
    }
}

async function loadPracticeSampleInLab(sampleId) {
    const btn = document.getElementById(`btn-load-sample-${sampleId}`);
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '⚙️ Analyzing Safe Binary...';
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
        if (labTitle) labTitle.textContent = `🔬 Active Practice Lab: ${data.sample_meta.title}`;

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
                            <span class="badge badge-low" style="margin-left: 8px; font-size: 10px;">🛡️ ZERO-EXECUTION SAFE</span>
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
                    <span class="metric-sub">${entropyVal > 7.2 ? '⚠️ High Randomness / Dense' : '✓ Uncompressed / Normal'}</span>
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
        <tr><td style="font-weight: 600; width: 220px;">Target Architecture</td><td><code>${escapeHtml(pe.machine_architecture || pe.machine || 'x86 (32-bit)')}</code></td></tr>
        <tr><td style="font-weight: 600;">Subsystem</td><td><code>${escapeHtml(pe.subsystem || 'Windows GUI / Console')}</code></td></tr>
        <tr><td style="font-weight: 600;">Address of Entry Point (EP)</td><td><code>${escapeHtml(pe.entry_point_rva || pe.entry_point || '0x00001000')}</code></td></tr>
        <tr><td style="font-weight: 600;">Preferred Image Base</td><td><code>${escapeHtml(pe.image_base || '0x00400000')}</code></td></tr>
        <tr><td style="font-weight: 600;">Compile Timestamp</td><td><code>${escapeHtml(pe.compile_time || pe.timestamp_iso || '2026-01-01')}</code></td></tr>
        <tr><td style="font-weight: 600;">Security Mitigations</td><td><code>ASLR: ${pe.aslr_enabled ? '✓ Enabled' : '✕ Disabled'} | DEP: ${pe.dep_enabled ? '✓ Enabled' : '✕ Disabled'}</code></td></tr>
    `;
}

function renderLabSections(sample) {
    const tbody = document.getElementById('lab-sections-tbody');
    if (!tbody) return;
    const sections = sample.sections || (sample.pe_headers && sample.pe_headers.sections) || [];
    if (sections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state-cell">No sections found in sample.</td></tr>';
        return;
    }
    tbody.innerHTML = sections.map(s => {
        const ent = s.entropy !== undefined ? Number(s.entropy).toFixed(2) : '-';
        const isHigh = s.entropy && s.entropy > 7.2;
        const wxViolation = s.characteristics_flags && (s.characteristics_flags.includes('WRITE') && s.characteristics_flags.includes('EXECUTE'));
        
        return `
            <tr>
                <td style="font-weight: 600; color: var(--accent-blue);"><code>${escapeHtml(s.name)}</code></td>
                <td>${formatBytes(s.virtual_size || 0)}</td>
                <td>${formatBytes(s.raw_size || s.size_of_raw_data || 0)}</td>
                <td style="font-weight: 700; color: ${isHigh ? '#f87171' : 'var(--text-primary)'};">${ent}</td>
                <td><span style="font-size: 11px; color: ${wxViolation ? '#f87171' : 'var(--text-muted)'};">${escapeHtml(s.permissions || s.characteristics_flags?.join(', ') || 'R-E')}</span></td>
                <td>${wxViolation ? '<span class="badge badge-crit">⚠️ W+X Permission</span>' : (isHigh ? '<span class="badge badge-high">⚠️ High Entropy</span>' : '<span class="badge badge-low">Normal</span>')}</td>
            </tr>
        `;
    }).join('');
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
                    <div style="font-weight: 700; color: var(--accent-blue); font-size: 13px; margin-bottom: 6px;">📦 ${escapeHtml(lib.dll_name || lib.name || 'Library')}</div>
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
                    <button type="button" class="btn-secondary" onclick="toggleQuizHint('${q.id}')" style="font-size: 10px; padding: 2px 8px;">💡 Hint</button>
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
        if (heading) heading.textContent = data.passed ? '🎓 Mastery Assessment: PASSED' : '📚 Mastery Assessment: Review Needed';
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
                resultEl.textContent = r.is_correct ? '✓ Correct' : '✕ Incorrect';
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
    const navHistory = document.getElementById('nav-item-history');
    const navAnalysis = document.getElementById('nav-item-analysis');
    const navPE = document.getElementById('nav-item-pe');
    const navImports = document.getElementById('nav-item-imports');
    const navStrings = document.getElementById('nav-item-strings');
    const navIndicators = document.getElementById('nav-item-indicators');
    const navAI = document.getElementById('nav-item-ai');
    const navLearning = document.getElementById('nav-item-learning');
    const navAdmin = document.getElementById('nav-item-admin');

    // Hide all navigation elements initially
    [navHome, navHistory, navAnalysis, navPE, navImports, navStrings, navIndicators, navAI, navLearning, navAdmin].forEach(el => {
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
        if (navHistory) {
            navHistory.style.display = 'block';
            const label = document.getElementById('nav-label-history');
            if (label) label.textContent = isAm ? 'የትንተና ታሪክ' : 'Analysis History';
        }
        if (navAnalysis) {
            navAnalysis.style.display = 'block';
            const label = document.getElementById('nav-label-analysis');
            if (label) label.textContent = isAm ? 'ትንተና እይታ' : 'Analysis Overview';
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
            if (label) label.textContent = isAm ? 'አዲስ ትንተና' : 'New Analysis / Intake';
        }
    } else if (role === 'ANALYST') {
        // ANALYST sees: Dashboard, New Analysis, Analysis History, Threat Intelligence, Reports, Learning Center
        if (navHome) {
            navHome.style.display = 'block';
            const label = document.getElementById('nav-label-home');
            if (label) label.textContent = isAm ? 'አዲስ ትንተና' : 'Dashboard / Intake';
        }
        if (navHistory) {
            navHistory.style.display = 'block';
            const label = document.getElementById('nav-label-history');
            if (label) label.textContent = isAm ? 'የትንተና ታሪክ' : 'Analysis History';
        }
        if (navAnalysis) {
            navAnalysis.style.display = 'block';
            const label = document.getElementById('nav-label-analysis');
            if (label) label.textContent = isAm ? 'ትንተና እይታ' : 'Analysis Overview';
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
        if (navHistory) {
            navHistory.style.display = 'block';
            const label = document.getElementById('nav-label-history');
            if (label) label.textContent = isAm ? 'የትንተና ታሪክ' : 'Analysis History';
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

        // Update Overview Counters
        const usersTotalEl = document.getElementById('admin-overview-users-total');
        const usersBreakdownEl = document.getElementById('admin-overview-users-breakdown');
        const samplesTotalEl = document.getElementById('admin-overview-samples-total');
        const indicatorsTotalEl = document.getElementById('admin-overview-indicators-total');
        const logsTotalEl = document.getElementById('admin-overview-logs-total');
        const alertsTotalEl = document.getElementById('admin-overview-alerts-total');
        const healthEl = document.getElementById('admin-overview-health');

        if (usersTotalEl) usersTotalEl.textContent = data.total_users || 0;
        if (usersBreakdownEl) {
            usersBreakdownEl.textContent = `${data.admin_count || 0} Admins • ${data.analyst_count || 0} Analysts • ${data.student_count || 0} Students (${data.active_users || 0} Active)`;
        }
        if (samplesTotalEl) samplesTotalEl.textContent = data.total_samples || 0;
        if (indicatorsTotalEl) indicatorsTotalEl.textContent = `${data.total_indicators || 0} Correlated Indicators`;
        if (logsTotalEl) logsTotalEl.textContent = data.total_audit_logs || 0;
        if (alertsTotalEl) alertsTotalEl.textContent = `${data.inactive_users || 0} Inactive • ${data.revoked_tokens_count || 0} Revoked Tokens`;
        if (healthEl) healthEl.textContent = data.system_health || 'OPTIMAL';

        // Render Recent Users in Overview
        const tbody = document.getElementById('admin-recent-users-tbody');
        if (tbody) {
            if (!data.recent_users || data.recent_users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="empty-state-cell">No users registered yet.</td></tr>';
            } else {
                tbody.innerHTML = data.recent_users.map(u => {
                    const roleBadgeClass = u.role === 'ADMIN' ? 'role-badge-admin' : (u.role === 'ANALYST' ? 'role-badge-analyst' : 'role-badge-student');
                    const dateStr = u.created_at ? u.created_at.replace('T', ' ').substring(0, 10) : '-';
                    return `
                        <tr>
                            <td style="font-weight: 600; color: var(--text-primary);">
                                ${escapeHtml(u.username)} ${state.user && u.id === state.user.id ? '<span style="font-size: 10px; color: var(--accent-blue); font-weight: 700;">(You)</span>' : ''}
                            </td>
                            <td><span class="role-badge ${roleBadgeClass}">${escapeHtml(u.role)}</span></td>
                            <td><span class="badge ${u.is_active ? 'badge-low' : 'badge-crit'}">${u.is_active ? 'ACTIVE' : 'INACTIVE'}</span></td>
                            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(dateStr)}</td>
                        </tr>
                    `;
                }).join('');
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
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state-cell">Access denied or failed to load users.</td></tr>';
            return;
        }
        state.adminUsersList = await res.json();
        const countBadge = document.getElementById('admin-users-count-badge');
        if (countBadge) countBadge.textContent = `${state.adminUsersList.length} platform identity record${state.adminUsersList.length === 1 ? '' : 's'}`;
        filterUsersTable();
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;
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
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state-cell">No matching platform users found.</td></tr>';
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
            statusBadge = '<span class="badge badge-high" title="Account locked due to failed attempts">🔒 LOCKED</span>';
        }

        const roleModalBtn = isCurrent ? '' : `
            <button class="btn-secondary" onclick="openAdminRoleModal(${u.id}, '${escapeHtml(u.username)}', '${escapeHtml(u.role)}')" style="font-size: 10px; padding: 2px 6px;" title="Change user role">
                🎭 Role
            </button>
        `;

        const resetPassBtn = `
            <button class="btn-secondary" onclick="openAdminResetPassModal(${u.id}, '${escapeHtml(u.username)}')" style="font-size: 10px; padding: 2px 6px;" title="Reset password">
                🔑 Password
            </button>
        `;

        const unlockBtn = isLocked ? `
            <button class="btn-secondary" onclick="handleAdminUnlockUser(${u.id}, '${escapeHtml(u.username)}')" style="font-size: 10px; padding: 2px 6px; color: var(--accent-blue); border-color: var(--accent-blue);" title="Clear failed attempts and unlock">
                🔓 Unlock
            </button>
        ` : '';

        const toggleBtn = isCurrent ? '' : `
            <button class="btn-secondary" onclick="toggleUserStatus(${u.id})" style="font-size: 10px; padding: 2px 6px;" title="${u.is_active ? 'Deactivate user' : 'Activate user'}">
                ${u.is_active ? '⏸️' : '▶️'}
            </button>
        `;

        const deleteBtn = isCurrent ? '' : `
            <button class="btn-secondary" onclick="deleteUserAccount(${u.id}, '${escapeHtml(u.username)}')" style="font-size: 10px; padding: 2px 6px; color: #f87171; border-color: rgba(239,68,68,0.3);" title="Delete user">
                🗑️
            </button>
        `;

        return `
            <tr>
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
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state-cell">Unable to load RBAC permissions matrix.</td></tr>';
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
                <tr>
                    <td style="font-weight: 600; color: var(--text-primary);">
                        <code>${escapeHtml(p.id)}</code>
                    </td>
                    <td style="font-size: 12px; color: var(--text-secondary);">
                        ${escapeHtml(p.description)}
                    </td>
                    <td style="text-align: center;">
                        ${hasAdmin ? '<span style="color: #10b981; font-weight: 700; font-size: 14px;">✓ Granted</span>' : '<span style="color: var(--text-muted);">—</span>'}
                    </td>
                    <td style="text-align: center;">
                        ${hasAnalyst ? '<span style="color: #06b6d4; font-weight: 700; font-size: 14px;">✓ Granted</span>' : '<span style="color: var(--text-muted);">—</span>'}
                    </td>
                    <td style="text-align: center;">
                        ${hasStudent ? '<span style="color: #10b981; font-weight: 700; font-size: 14px;">✓ Granted</span>' : '<span style="color: var(--text-muted);">—</span>'}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;
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
        if (dbSubEl) dbSubEl.textContent = `${data.database_samples_count || 0} sample rows • ${data.audit_logs_count || 0} audit logs`;
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
            if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="empty-state-cell">Access denied or failed to load audit logs.</td></tr>';
            return;
        }

        const data = await logsRes.json();
        if (!data.items || data.items.length === 0) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="empty-state-cell">No matching audit events recorded yet.</td></tr>';
            return;
        }

        if (tbody) {
            tbody.innerHTML = data.items.map(item => {
                const resClass = getAuditResultBadgeClass(item.result);
                const userDisplay = item.username ? `${escapeHtml(item.username)} (#${item.user_id})` : (item.ip_address || 'System / Anon');
                const detailsEncoded = encodeURIComponent(JSON.stringify(item.details || {}));

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
                        <td style="font-size: 11px; color: var(--text-secondary); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            ${escapeHtml(JSON.stringify(item.details || {}))}
                        </td>
                        <td style="text-align: right;">
                            <button class="btn-secondary" onclick="openAuditDetailModal('${detailsEncoded}')" style="font-size: 10px; padding: 2px 6px;">
                                🔍 Inspect
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;
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


