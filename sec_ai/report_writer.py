from fpdf import FPDF
import datetime
import os

class VrthaPDFReport(FPDF):
    def header(self):
        # Logo placeholder or Title
        self.set_font('helvetica', 'B', 20)
        self.set_text_color(0, 102, 204)
        self.cell(0, 10, 'VṚTHĀ - SECURITY ASSESSMENT REPORT', ln=True, align='C')
        self.set_font('helvetica', 'I', 10)
        self.set_text_color(100)
        self.cell(0, 10, 'Advanced WordPress VAPT Framework v2.1', ln=True, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()} | Confidential | Generated on {datetime.date.today()}', 0, 0, 'C')

def generate_pdf_report(markdown_content, output_path, target_domain):
    pdf = VrthaPDFReport()
    pdf.add_page()
    
    # Title Page
    pdf.ln(40)
    pdf.set_font('helvetica', 'B', 24)
    pdf.set_text_color(0)
    pdf.cell(0, 20, f'Target: {target_domain}', ln=True, align='C')
    pdf.ln(10)
    pdf.set_font('helvetica', '', 14)
    pdf.cell(0, 10, f'Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
    pdf.ln(30)
    
    # Disclaimer
    pdf.set_font('helvetica', 'B', 12)
    pdf.cell(0, 10, 'CONFIDENTIALITY NOTICE', ln=True, align='C')
    pdf.set_font('helvetica', '', 10)
    disclaimer = ("This report is confidential and intended solely for the use of the individual or "
                  "entity to whom it is addressed. It contains highly sensitive security information. "
                  "Unauthorized use, dissemination, or reproduction is strictly prohibited.")
    pdf.multi_cell(0, 5, disclaimer, align='C')
    
    pdf.add_page()
    
    # Content
    # We'll do a basic markdown to PDF conversion here for simplicity.
    # A more robust one would handle styling, but for now we focus on readability.
    
    lines = markdown_content.split('\n')
    for line in lines:
        if line.startswith('# '):
            pdf.ln(5)
            pdf.set_font('helvetica', 'B', 18)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, line[2:], ln=True)
            pdf.ln(2)
        elif line.startswith('## '):
            pdf.ln(3)
            pdf.set_font('helvetica', 'B', 14)
            pdf.set_text_color(0)
            pdf.cell(0, 10, line[3:], ln=True)
        elif line.startswith('### '):
            pdf.set_font('helvetica', 'B', 12)
            pdf.set_text_color(50)
            pdf.cell(0, 8, line[4:], ln=True)
        elif line.startswith('---'):
            pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 190, pdf.get_y())
            pdf.ln(2)
        elif line.startswith('```'):
            pdf.set_font('courier', '', 9)
            pdf.set_text_color(0, 51, 0)
            continue # Simple skip backticks
        else:
            pdf.set_font('helvetica', '', 10)
            pdf.set_text_color(0)
            # Handle bullet points
            if line.strip().startswith('- '):
                pdf.cell(5)
                pdf.multi_cell(185, 5, chr(149) + " " + line.strip()[2:])
            elif line.strip().startswith('* '):
                pdf.cell(5)
                pdf.multi_cell(185, 5, chr(149) + " " + line.strip()[2:])
            else:
                pdf.multi_cell(0, 5, line)
        
        # Check if we need a new page
        if pdf.get_y() > 250:
            pdf.add_page()

    pdf.output(output_path)
    return output_path
