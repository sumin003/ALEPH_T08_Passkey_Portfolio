/* 모바일 메뉴 */
const menuToggle = document.getElementById("menuToggle");
const menu = document.getElementById("menu");

if (menuToggle && menu) {
    menuToggle.addEventListener("click", () => {
        const isOpen = menu.classList.toggle("open");

        menuToggle.setAttribute("aria-expanded", String(isOpen));
        menuToggle.setAttribute(
            "aria-label",
            isOpen ? "메뉴 닫기" : "메뉴 열기"
        );
    });

    menu.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", () => {
            menu.classList.remove("open");
            menuToggle.setAttribute("aria-expanded", "false");
            menuToggle.setAttribute("aria-label", "메뉴 열기");
        });
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            menu.classList.remove("open");
            menuToggle.setAttribute("aria-expanded", "false");
            menuToggle.setAttribute("aria-label", "메뉴 열기");
        }
    });

    window.addEventListener("resize", () => {
        if (window.innerWidth > 760) {
            menu.classList.remove("open");
            menuToggle.setAttribute("aria-expanded", "false");
            menuToggle.setAttribute("aria-label", "메뉴 열기");
        }
    });
}

/* 경험 탭 */
const experienceButtons = Array.from(
    document.querySelectorAll(".exp-btn")
);

const experienceItems = Array.from(
    document.querySelectorAll(".experience-item")
);

function selectExperience(button) {
    const targetId = button.dataset.exp;

    experienceButtons.forEach((item) => {
        const selected = item === button;

        item.classList.toggle("active", selected);
        item.setAttribute("aria-selected", String(selected));
        item.tabIndex = selected ? 0 : -1;
    });

    experienceItems.forEach((item) => {
        const selected = item.id === targetId;

        item.classList.toggle("active", selected);
        item.hidden = !selected;
    });
}

experienceButtons.forEach((button, index) => {
    button.addEventListener("click", () => {
        selectExperience(button);
    });

    button.addEventListener("keydown", (event) => {
        let targetIndex = index;

        if (event.key === "ArrowRight") {
            targetIndex = (index + 1) % experienceButtons.length;
        } else if (event.key === "ArrowLeft") {
            targetIndex =
                (index - 1 + experienceButtons.length) %
                experienceButtons.length;
        } else if (event.key === "Home") {
            targetIndex = 0;
        } else if (event.key === "End") {
            targetIndex = experienceButtons.length - 1;
        } else {
            return;
        }

        event.preventDefault();

        experienceButtons[targetIndex].focus();
        selectExperience(experienceButtons[targetIndex]);
    });
});

/* 근거보기 */
const evidenceToggles = document.querySelectorAll(
    ".evidence-toggle"
);

evidenceToggles.forEach((button) => {
    button.addEventListener("click", () => {
        const evidenceId = button.getAttribute("aria-controls");
        const evidence = document.getElementById(evidenceId);

        if (!evidence) {
            return;
        }

        const isOpen =
            button.getAttribute("aria-expanded") === "true";

        const nextOpenState = !isOpen;

        button.setAttribute(
            "aria-expanded",
            String(nextOpenState)
        );

        evidence.hidden = !nextOpenState;

        const text = button.querySelector(
            ".evidence-toggle-text"
        );

        const icon = button.querySelector(
            ".evidence-toggle-icon"
        );

        if (text) {
            text.textContent = nextOpenState
                ? "근거닫기"
                : "근거보기";
        }

        if (icon) {
            icon.textContent = nextOpenState ? "−" : "＋";
        }
    });
});

/* 움직임 줄이기 */
const motionToggle = document.getElementById("motionToggle");

const motionPreference = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
);

let reduceMotion = motionPreference.matches;
let manualMotionChoice = false;

function applyMotionPreference() {
    document.documentElement.classList.toggle(
        "reduce-motion",
        reduceMotion
    );

    if (!motionToggle) {
        return;
    }

    motionToggle.setAttribute(
        "aria-pressed",
        String(reduceMotion)
    );

    motionToggle.textContent = reduceMotion
        ? "움직임 줄이기: 켜짐"
        : "움직임 줄이기: 꺼짐";
}

if (motionToggle) {
    motionToggle.addEventListener("click", () => {
        manualMotionChoice = true;
        reduceMotion = !reduceMotion;
        applyMotionPreference();
    });
}

motionPreference.addEventListener("change", (event) => {
    if (!manualMotionChoice) {
        reduceMotion = event.matches;
        applyMotionPreference();
    }
});

applyMotionPreference();

/* 첫 화면 연락처 */
const contactButtons = document.querySelectorAll(
    ".contact-btn"
);

const contactDisplay = document.getElementById(
    "contact-info-display"
);

contactButtons.forEach((button) => {
    button.addEventListener("click", () => {
        if (!contactDisplay) {
            return;
        }

        const contactType = button.dataset.contact;
        const isOpen =
            button.getAttribute("aria-expanded") === "true";

        contactButtons.forEach((item) => {
            item.setAttribute("aria-expanded", "false");
        });

        if (isOpen) {
            contactDisplay.hidden = true;
            contactDisplay.replaceChildren();
            return;
        }

        button.setAttribute("aria-expanded", "true");
        contactDisplay.hidden = false;
        contactDisplay.replaceChildren();

        if (contactType === "github") {
            const link = document.createElement("a");

            link.href =
                "https://github.com/sumin003?tab=repositories";

            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = "GitHub 둘러보기 ↗";

            contactDisplay.appendChild(link);
        }

        if (contactType === "email") {
            contactDisplay.textContent =
                "sumin0516a@naver.com";
        }
    });
});

