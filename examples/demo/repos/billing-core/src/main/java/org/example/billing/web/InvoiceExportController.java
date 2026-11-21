package org.example.billing.web;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Выгрузка счетов и отчётов в PDF, приветственная страница личного кабинета.
 */
public class InvoiceExportController extends HttpServlet {

    private static final Path EXPORT_DIR = Paths.get("/var/lib/billing/exports").toAbsolutePath().normalize();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        if ("invoice".equals(action)) {
            downloadInvoice(request, response);
        } else if ("report".equals(action)) {
            downloadReport(request, response);
        } else {
            showGreeting(request, response);
        }
    }

    private void downloadInvoice(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        File invoice = new File(EXPORT_DIR.toFile(), fileName);
        response.setContentType("application/pdf");
        Files.copy(invoice.toPath(), response.getOutputStream());
    }

    private void downloadReport(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        Path report = EXPORT_DIR.resolve(fileName).normalize();
        if (!report.startsWith(EXPORT_DIR) || !Files.isRegularFile(report)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        response.setContentType("application/pdf");
        Files.copy(report, response.getOutputStream());
    }

    private void showGreeting(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.write("<p>Здравствуйте, " + name + "!</p>");
    }
}
