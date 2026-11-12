import os

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Inches, Pt


OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PATH = os.path.join(
    os.path.dirname(OUTPUT_DIR), "Web_Attack_Detection_Browser_AI_Agents.pptx"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

NAVY = RGBColor(26, 43, 54)
DARK_GRAY = RGBColor(40, 40, 40)
WHITE = RGBColor(255, 255, 255)
MUTED_RED = RGBColor(150, 50, 50)
blank_layout = prs.slide_layouts[6]


def add_slide_header(slide, title_text):
    textbox = slide.shapes.add_textbox(
        Inches(0.5), Inches(0.4), Inches(12.333), Inches(1)
    )
    textbox.text_frame.word_wrap = True
    paragraph = textbox.text_frame.paragraphs[0]
    paragraph.text = title_text
    paragraph.font.size = Pt(36)
    paragraph.font.bold = True
    paragraph.font.color.rgb = NAVY
    paragraph.font.name = "Arial"


def add_bullets(
    text_frame,
    items,
    font_size=15,
    space_after=6,
    use_first_paragraph=True,
    bullet=True,
):
    for index, item in enumerate(items):
        paragraph = (
            text_frame.paragraphs[0]
            if index == 0 and use_first_paragraph
            else text_frame.add_paragraph()
        )
        paragraph.text = f"• {item}" if bullet else item
        paragraph.level = 0
        paragraph.font.size = Pt(font_size)
        paragraph.font.color.rgb = DARK_GRAY
        paragraph.space_after = Pt(space_after)


# Slide 1: Title and team details
slide = prs.slides.add_slide(blank_layout)
title_box = slide.shapes.add_textbox(
    Inches(1.0), Inches(1.8), Inches(11.333), Inches(1.5)
)
title_frame = title_box.text_frame
title_frame.word_wrap = True
title = title_frame.paragraphs[0]
title.text = "Web Attack Detection Using Browser AI Agents"
title.font.size = Pt(44)
title.font.bold = True
title.font.color.rgb = NAVY

subtitle = title_frame.add_paragraph()
subtitle.text = "Research and Methodology"
subtitle.font.size = Pt(24)
subtitle.font.color.rgb = DARK_GRAY
subtitle.space_before = Pt(10)

team_box = slide.shapes.add_textbox(
    Inches(1.0), Inches(4.2), Inches(6.0), Inches(2.5)
)
team_frame = team_box.text_frame
team_heading = team_frame.paragraphs[0]
team_heading.text = "Team Members:"
team_heading.font.bold = True
team_heading.font.size = Pt(16)
team_heading.font.color.rgb = NAVY
add_bullets(
    team_frame,
    ["Atreya AVS", "Kruthik S", "Ayushman Patel", "Prudhvi Sai", "C Athish"],
    font_size=14,
    space_after=2,
    use_first_paragraph=False,
)

institution_box = slide.shapes.add_textbox(
    Inches(7.5), Inches(4.2), Inches(5.0), Inches(2.5)
)
institution_frame = institution_box.text_frame
institution = institution_frame.paragraphs[0]
institution.text = (
    "School of Computer Science and Engineering\nRV University, Bangalore"
)
institution.font.size = Pt(14)
institution.font.color.rgb = DARK_GRAY

instructor = institution_frame.add_paragraph()
instructor.text = "\nCourse Instructor:\nProf. ABC\nAssistant Professor"
instructor.font.size = Pt(14)
instructor.font.bold = True
instructor.font.color.rgb = NAVY

# Slide 2: Abstract
slide = prs.slides.add_slide(blank_layout)
add_slide_header(slide, "Abstract")
content_box = slide.shapes.add_textbox(
    Inches(0.7), Inches(1.8), Inches(11.933), Inches(5.0)
)
content_frame = content_box.text_frame
content_frame.word_wrap = True
add_bullets(
    content_frame,
    [
        "Web applications face security risks such as cross-site scripting (XSS), SQL injection, and broken access control.",
        "Traditional scanners often rely on predefined rules and may overlook application-specific behavior.",
        "This project proposes an AI-assisted browser agent that explores web applications and performs targeted security checks.",
        "The system combines browser automation, five vulnerability detectors, and Groq-based AI analysis.",
        "Its objective is to produce an explainable security assessment containing findings, evidence, severity, and remediation guidance.",
    ],
    font_size=18,
    space_after=14,
)

# Slide 3: Introduction, problem statement, and hypothesis
slide = prs.slides.add_slide(blank_layout)
add_slide_header(slide, "Introduction, Problem Statement & Hypothesis")

intro_box = slide.shapes.add_textbox(
    Inches(0.7), Inches(1.6), Inches(5.8), Inches(5.2)
)
intro_frame = intro_box.text_frame
intro_frame.word_wrap = True
intro_heading = intro_frame.paragraphs[0]
intro_heading.text = "Introduction"
intro_heading.font.bold = True
intro_heading.font.size = Pt(20)
intro_heading.font.color.rgb = NAVY

intro_body = intro_frame.add_paragraph()
intro_body.text = (
    "Web applications contain interactive elements such as login forms, "
    "user profiles, links, and input fields. Testing these applications "
    "requires understanding their structure and behavior."
)
intro_body.font.size = Pt(15)
intro_body.font.color.rgb = DARK_GRAY
intro_body.space_before = Pt(8)

problem_heading = intro_frame.add_paragraph()
problem_heading.text = "\nProblem Statement"
problem_heading.font.bold = True
problem_heading.font.size = Pt(20)
problem_heading.font.color.rgb = NAVY
add_bullets(
    intro_frame,
    [
        "Manual security testing is time-consuming and requires specialized skills.",
        "Rule-based scanners may miss context-dependent vulnerabilities.",
        "Large applications contain many pages and input points, making comprehensive testing difficult.",
    ],
    font_size=14,
    space_after=5,
    use_first_paragraph=False,
)

hypothesis_box = slide.shapes.add_textbox(
    Inches(6.8), Inches(1.6), Inches(5.8), Inches(5.2)
)
hypothesis_frame = hypothesis_box.text_frame
hypothesis_frame.word_wrap = True
hypothesis_heading = hypothesis_frame.paragraphs[0]
hypothesis_heading.text = "Hypothesis"
hypothesis_heading.font.bold = True
hypothesis_heading.font.size = Pt(20)
hypothesis_heading.font.color.rgb = NAVY

hypothesis_body = hypothesis_frame.add_paragraph()
hypothesis_body.text = (
    "An AI-assisted browser agent that explores web applications before "
    "performing targeted vulnerability checks can provide more "
    "context-aware and explainable security assessments than relying "
    "solely on predefined scanning rules."
)
hypothesis_body.font.size = Pt(16)
hypothesis_body.font.color.rgb = DARK_GRAY
hypothesis_body.space_before = Pt(10)

hypothesis_note = hypothesis_frame.add_paragraph()
hypothesis_note.text = (
    "\nNote: This is the project's proposed hypothesis, not a proven "
    "experimental result."
)
hypothesis_note.font.size = Pt(13)
hypothesis_note.font.italic = True
hypothesis_note.font.color.rgb = MUTED_RED

# Slide 4: System architecture and workflow
slide = prs.slides.add_slide(blank_layout)
add_slide_header(slide, "Methodology: System Architecture & Workflow")

architecture_box = slide.shapes.add_textbox(
    Inches(0.7), Inches(1.6), Inches(5.8), Inches(5.2)
)
architecture_frame = architecture_box.text_frame
architecture_frame.word_wrap = True
architecture_heading = architecture_frame.paragraphs[0]
architecture_heading.text = "System Architecture"
architecture_heading.font.bold = True
architecture_heading.font.size = Pt(20)
architecture_heading.font.color.rgb = NAVY
add_bullets(
    architecture_frame,
    [
        "Frontend: React, TypeScript, and Vite",
        "Backend: Node.js and Express",
        "Browser Automation: Stagehand and Playwright",
        "AI Analysis: Groq API",
        "Data & Communication: SQLite and WebSocket",
    ],
    font_size=15,
    space_after=6,
    use_first_paragraph=False,
)

workflow_box = slide.shapes.add_textbox(
    Inches(6.8), Inches(1.6), Inches(5.8), Inches(5.2)
)
workflow_frame = workflow_box.text_frame
workflow_frame.word_wrap = True
workflow_heading = workflow_frame.paragraphs[0]
workflow_heading.text = "Workflow Engine Steps"
workflow_heading.font.bold = True
workflow_heading.font.size = Pt(20)
workflow_heading.font.color.rgb = NAVY
add_bullets(
    workflow_frame,
    [
        "1. User submits target web app entry URL.",
        "2. Browser agent provisions headless Chromium runtime.",
        "3. Exploration engine systematically catalogs maps and structural scopes.",
        "4. Groq parses discovery metrics to prioritize target pages.",
        "5. Security executor runs five vulnerability detectors.",
        "6. Context engine synthesizes findings into UI dashboard logs.",
    ],
    font_size=14,
    space_after=6,
    use_first_paragraph=False,
    bullet=False,
)

# Slide 5: Vulnerability detection and AI analysis
slide = prs.slides.add_slide(blank_layout)
add_slide_header(slide, "Methodology: Vulnerability Detection & AI Analysis")

table_shape = slide.shapes.add_table(
    6, 2, Inches(0.7), Inches(1.6), Inches(6.5), Inches(4.5)
)
table = table_shape.table
table.columns[0].width = Inches(1.8)
table.columns[1].width = Inches(4.7)

for column_index, heading in enumerate(["Detector", "Purpose"]):
    cell = table.cell(0, column_index)
    cell.text = heading
    cell.fill.solid()
    cell.fill.fore_color.rgb = NAVY
    paragraph = cell.text_frame.paragraphs[0]
    paragraph.font.bold = True
    paragraph.font.color.rgb = WHITE
    paragraph.font.size = Pt(14)

detectors = [
    ("XSS", "Checks reflected input and risky DOM patterns."),
    ("SQL Injection", "Looks for database error signatures after controlled inputs."),
    ("IDOR", "Checks whether changing object identifiers exposes unauthorized resources."),
    ("Security headers", "Checks CSP, HSTS, and other browser security headers."),
    ("Insecure cookies", "Inspects HttpOnly, Secure, and SameSite attributes."),
]
for row_index, (detector, purpose) in enumerate(detectors, start=1):
    for column_index, value in enumerate((detector, purpose)):
        cell = table.cell(row_index, column_index)
        cell.text = value
        cell.text_frame.paragraphs[0].font.size = Pt(12)
        cell.text_frame.paragraphs[0].font.color.rgb = DARK_GRAY

ai_box = slide.shapes.add_textbox(
    Inches(7.5), Inches(1.6), Inches(5.2), Inches(4.5)
)
ai_frame = ai_box.text_frame
ai_frame.word_wrap = True
ai_heading = ai_frame.paragraphs[0]
ai_heading.text = "AI Enrichment (Groq)"
ai_heading.font.bold = True
ai_heading.font.size = Pt(18)
ai_heading.font.color.rgb = NAVY

ai_body = ai_frame.add_paragraph()
ai_body.text = (
    "Groq helps prioritize pages, interpret technical findings, estimate "
    "severity and confidence, and generate clear explanations and "
    "remediation recommendations."
)
ai_body.font.size = Pt(14)
ai_body.font.color.rgb = DARK_GRAY
ai_body.space_before = Pt(8)

# Slide 6: Results and discussion
slide = prs.slides.add_slide(blank_layout)
add_slide_header(slide, "Results and Discussion")

results_box = slide.shapes.add_textbox(
    Inches(0.7), Inches(1.7), Inches(11.9), Inches(1.1)
)
results_frame = results_box.text_frame
results_frame.word_wrap = True
results_frame.paragraphs[0].text = (
    "The supplied project description does not include measured "
    "experimental results. No performance claims are made here."
)
results_frame.paragraphs[0].font.size = Pt(18)
results_frame.paragraphs[0].font.bold = True
results_frame.paragraphs[0].font.color.rgb = NAVY

evaluation_box = slide.shapes.add_textbox(
    Inches(0.7), Inches(3.0), Inches(5.8), Inches(3.5)
)
evaluation_frame = evaluation_box.text_frame
evaluation_frame.word_wrap = True
evaluation_heading = evaluation_frame.paragraphs[0]
evaluation_heading.text = "Evaluation to Report"
evaluation_heading.font.bold = True
evaluation_heading.font.size = Pt(20)
evaluation_heading.font.color.rgb = NAVY
add_bullets(
    evaluation_frame,
    [
        "Precision and recall against manually verified findings.",
        "Coverage: pages and input points explored.",
        "Runtime and false-positive rate by detector.",
        "Comparison with a rule-based baseline.",
    ],
    font_size=15,
    space_after=8,
    use_first_paragraph=False,
)

discussion_box = slide.shapes.add_textbox(
    Inches(6.8), Inches(3.0), Inches(5.8), Inches(3.5)
)
discussion_frame = discussion_box.text_frame
discussion_frame.word_wrap = True
discussion_heading = discussion_frame.paragraphs[0]
discussion_heading.text = "Discussion"
discussion_heading.font.bold = True
discussion_heading.font.size = Pt(20)
discussion_heading.font.color.rgb = NAVY
discussion_body = discussion_frame.add_paragraph()
discussion_body.text = (
    "AI-generated severity and remediation guidance should be treated "
    "as analyst assistance. Validate each finding against evidence and "
    "authorized test scope before drawing conclusions."
)
discussion_body.font.size = Pt(16)
discussion_body.font.color.rgb = DARK_GRAY
discussion_body.space_before = Pt(10)

prs.save(OUTPUT_PATH)
print(f"Created {OUTPUT_PATH}")
