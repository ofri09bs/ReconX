#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include "db_manager.h"

#define DATABASE_PATH "reconx.db"

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

int print_callback(void *data, int argc, char **argv, char **azColName) {
    (void) data; // unused parameter
    for (int i = 0; i < argc; i++) {
        printf("%s: %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}


int init_database() {
    sqlite3 *db;
    char *error_msg = NULL;

    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    const char *sql_scan_query = 
        "CREATE TABLE IF NOT EXISTS scans("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "target TEXT NOT NULL, "
        "scan_type TEXT NOT NULL, "
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);";

    rc = sqlite3_exec(db, sql_scan_query, 0, 0, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Failed to create scans table: %s\n" RESET, error_msg);
        sqlite3_free(error_msg);
        sqlite3_close(db);
        return -1;
    }

    const char *sql_results_query = 
        "CREATE TABLE IF NOT EXISTS results("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "scan_id INTEGER NOT NULL, "
        "data TEXT NOT NULL, "
        "extra_info TEXT, "
        "FOREIGN KEY(scan_id) REFERENCES scans(id));";


    rc = sqlite3_exec(db, sql_results_query,0,0,&error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Failed to create results table: %s\n" RESET, error_msg);
        sqlite3_free(error_msg);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    return 0;
}


int create_new_scan(const char* target, const char* scan_type, char* timestamp) {
    sqlite3 *db;
    char *error_msg = NULL;

    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char query[256];
    snprintf(query, sizeof(query), "INSERT INTO scans (target, scan_type, timestamp) VALUES ('%s', '%s', '%s');", target, scan_type, timestamp);

    rc = sqlite3_exec(db, query, 0, 0, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Failed to insert new scan: %s\n" RESET, error_msg);
        sqlite3_free(error_msg);
        sqlite3_close(db);
        return -1;
    }

    int scan_id = (int)sqlite3_last_insert_rowid(db);
    //printf("[DEBUG] Created new scan with ID: %d\n", scan_id);
    sqlite3_close(db);
    return scan_id;
}

int save_scan_result(int scan_id, const char* data, const char* extra_info) {
    sqlite3 *db;
    char *error_msg = NULL;

    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char query[512];
    snprintf(query, sizeof(query), "INSERT INTO results (scan_id, data, extra_info) VALUES (%d, '%s', '%s');", scan_id, data, extra_info);

    rc = sqlite3_exec(db, query, 0, 0, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Failed to insert scan result: %s\n" RESET, error_msg);
        sqlite3_free(error_msg);
        sqlite3_close(db);
        return -1;
    }

    //printf("[DEBUG] Saved scan result to database: %s\n", data);

    sqlite3_close(db);
    return 0;
}

int show_data(int id, char* table_name) {
    sqlite3 *db;
    char *error_msg = NULL;

    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    char query[256];
    if (strcmp(table_name, "results") == 0) {
        snprintf(query, sizeof(query), "SELECT * FROM %s WHERE scan_id = %d;", table_name, id);
    } else {
        snprintf(query, sizeof(query), "SELECT * FROM %s WHERE id = %d;", table_name, id);
    }

    rc = sqlite3_exec(db, query, print_callback, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Failed to retrieve data: %s\n" RESET, error_msg);
        sqlite3_free(error_msg);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    return 0;
}

int show_scan_report(int scan_id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    
    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database\n" RESET);
        return -1;
    }

    char query_scan[256];
    snprintf(query_scan, sizeof(query_scan), "SELECT target, scan_type, timestamp FROM scans WHERE id = %d;", scan_id);

    rc = sqlite3_prepare_v2(db, query_scan, -1, &stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *target = sqlite3_column_text(stmt, 0);
        const unsigned char *scan_type = sqlite3_column_text(stmt, 1);
        const unsigned char *timestamp = sqlite3_column_text(stmt, 2);

        printf(YELLOW "\n========================================================================\n" RESET);
        printf(BOLD CYAN "[*] SCAN #%d " RESET "| Target: " GREEN "%s" RESET " | Type: %s | Time: %s\n", 
               scan_id, target, scan_type, timestamp);
        printf(YELLOW "========================================================================\n" RESET);
    } else {
        printf(RED "[-] Scan ID %d not found.\n" RESET, scan_id);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_finalize(stmt); 

    char query_results[256];
    snprintf(query_results, sizeof(query_results), "SELECT data, extra_info FROM results WHERE scan_id = %d;", scan_id);

    rc = sqlite3_prepare_v2(db, query_results, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *data = sqlite3_column_text(stmt, 0);
            const unsigned char *extra_info = sqlite3_column_text(stmt, 1);

            printf(GREEN "  [+] " RESET "%s", data);
            
            if (extra_info && strlen((const char*)extra_info) > 0) {
                printf(BLUE " (%s)" RESET, extra_info);
            }
            printf("\n");
            count++;
        }
        
        if (count == 0) {
            printf(YELLOW "  [-] No results found for this scan.\n" RESET);
        }
    } else {
        fprintf(stderr, RED "[-] Failed to retrieve results.\n" RESET);
    }
    
    sqlite3_finalize(stmt);
    printf(YELLOW "========================================================================\n\n" RESET);

    sqlite3_close(db);
    return 0;
}

int show_scan_history() {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    
    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database\n" RESET);
        return -1;
    }

    const char *query = "SELECT id, target, scan_type, timestamp FROM scans ORDER BY id ASC;";

    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        printf(YELLOW "\n--- ReconX Scan History ---\n" RESET);
        printf(CYAN "%-5s | %-25s | %-20s | %-20s\n" RESET, "ID", "TARGET", "TYPE", "TIMESTAMP");
        printf("-------------------------------------------------------------------------------\n");

        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            const unsigned char *target = sqlite3_column_text(stmt, 1);
            const unsigned char *scan_type = sqlite3_column_text(stmt, 2);
            const unsigned char *timestamp = sqlite3_column_text(stmt, 3);

            printf("%-5d | %-25s | %-20s | %-20s\n", id, target, scan_type, timestamp);
            count++;
        }
        
        if (count == 0) {
            printf(YELLOW "  No scans found in history. Go hack something!\n" RESET);
        }
        printf("-------------------------------------------------------------------------------\n\n");
    } else {
        fprintf(stderr, RED "[-] Failed to retrieve history.\n" RESET);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

void reset_database() {
    if (remove(DATABASE_PATH) == 0) {
        printf(GREEN "Database reset successfully.\n" RESET);
    } else {
        fprintf(stderr, RED "Failed to reset database.\n" RESET);
    }
}


int export_scan_report(int scan_id, const char *filename) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    
    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database\n" RESET);
        return -1;
    }

    char query_scan[256];
    snprintf(query_scan, sizeof(query_scan), "SELECT target, scan_type, timestamp FROM scans WHERE id = %d;", scan_id);

    rc = sqlite3_prepare_v2(db, query_scan, -1, &stmt, NULL);
    if (rc != SQLITE_OK || sqlite3_step(stmt) != SQLITE_ROW) {
        printf(RED "[-] Scan ID %d not found.\n" RESET, scan_id);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    const unsigned char *target = sqlite3_column_text(stmt, 0);
    const unsigned char *scan_type = sqlite3_column_text(stmt, 1);
    const unsigned char *timestamp = sqlite3_column_text(stmt, 2);

    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        printf(RED "[-] Failed to create HTML file: %s\n" RESET, filename);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    fprintf(fp, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    fprintf(fp, "    <meta charset=\"UTF-8\">\n");
    fprintf(fp, "    <title>ReconX Report - Scan #%d</title>\n", scan_id);
    fprintf(fp, "    <style>\n");
    fprintf(fp, "        body { font-family: 'Consolas', 'Courier New', monospace; background-color: #121212; color: #e0e0e0; margin: 40px; }\n");
    fprintf(fp, "        h1 { color: #00ffcc; border-bottom: 2px solid #333; padding-bottom: 10px; }\n");
    fprintf(fp, "        .metadata { background-color: #1e1e1e; padding: 20px; border-left: 5px solid #00ffcc; border-radius: 4px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }\n");
    fprintf(fp, "        .metadata p { margin: 5px 0; font-size: 16px; }\n");
    fprintf(fp, "        .highlight { color: #00ffcc; font-weight: bold; }\n");
    fprintf(fp, "        table { width: 100%%; border-collapse: collapse; margin-top: 20px; background-color: #1e1e1e; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }\n");
    fprintf(fp, "        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #333; }\n");
    fprintf(fp, "        th { background-color: #252525; color: #00ffcc; text-transform: uppercase; letter-spacing: 1px; }\n");
    fprintf(fp, "        tr:hover { background-color: #2a2a2a; }\n");
    fprintf(fp, "        .footer { margin-top: 50px; font-size: 12px; color: #666; text-align: center; }\n");
    fprintf(fp, "    </style>\n");
    fprintf(fp, "</head>\n<body>\n");

    fprintf(fp, "    <h1>ReconX Automated Security Report</h1>\n");
    fprintf(fp, "    <div class=\"metadata\">\n");
    fprintf(fp, "        <p><span class=\"highlight\">Target:</span> %s</p>\n", target);
    fprintf(fp, "        <p><span class=\"highlight\">Scan Type:</span> %s</p>\n", scan_type);
    fprintf(fp, "        <p><span class=\"highlight\">Timestamp:</span> %s</p>\n", timestamp);
    fprintf(fp, "        <p><span class=\"highlight\">Scan ID:</span> %d</p>\n", scan_id);
    fprintf(fp, "    </div>\n");

    sqlite3_finalize(stmt); 

    char query_results[256];
    snprintf(query_results, sizeof(query_results), "SELECT data, extra_info FROM results WHERE scan_id = %d;", scan_id);

    fprintf(fp, "    <table>\n");
    fprintf(fp, "        <thead>\n            <tr>\n                <th>Finding / Data</th>\n                <th>Extra Information</th>\n            </tr>\n        </thead>\n        <tbody>\n");

    rc = sqlite3_prepare_v2(db, query_results, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *data = sqlite3_column_text(stmt, 0);
            const unsigned char *extra_info = sqlite3_column_text(stmt, 1);
            
            const char *extra_str = (extra_info && strlen((const char*)extra_info) > 0) ? (const char*)extra_info : "N/A";

            fprintf(fp, "            <tr>\n");
            fprintf(fp, "                <td>%s</td>\n", data);
            fprintf(fp, "                <td>%s</td>\n", extra_str);
            fprintf(fp, "            </tr>\n");
            count++;
        }
        
        if (count == 0) {
            fprintf(fp, "            <tr><td colspan=\"2\" style=\"text-align: center; color: #ff4444;\">No results found for this scan.</td></tr>\n");
        }
    }

    fprintf(fp, "        </tbody>\n    </table>\n");
    
    fprintf(fp, "    <div class=\"footer\">Generated by ReconX Framework - Coded in C</div>\n");
    fprintf(fp, "</body>\n</html>\n");

    fclose(fp);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    printf(GREEN "[+] Report successfully exported to: %s\n" RESET, filename);
    return 0;
}

int export_scan_report_range(int start_id, int end_id, const char *filename) {
    sqlite3 *db;
    sqlite3_stmt *stmt_scan;
    sqlite3_stmt *stmt_results;
    
    int rc = sqlite3_open(DATABASE_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, RED "[-] Cannot open database\n" RESET);
        return -1;
    }

    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        printf(RED "[-] Failed to create HTML file: %s\n" RESET, filename);
        sqlite3_close(db);
        return -1;
    }

    fprintf(fp, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    fprintf(fp, "    <meta charset=\"UTF-8\">\n");
    fprintf(fp, "    <title>ReconX Report | Scans %d-%d</title>\n", start_id, end_id);
    fprintf(fp, "    <style>\n");
    fprintf(fp, "        body { font-family: 'Consolas', 'Courier New', monospace; background-color: #121212; color: #e0e0e0; margin: 40px; }\n");
    fprintf(fp, "        h1 { color: #00ffcc; border-bottom: 2px solid #333; padding-bottom: 10px; }\n");
    fprintf(fp, "        .scan-container { background-color: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 20px; margin-bottom: 40px; box-shadow: 0 4px 6px rgba(0,0,0,0.5); }\n");
    fprintf(fp, "        .metadata { border-left: 5px solid #00ffcc; padding-left: 15px; margin-bottom: 20px; }\n");
    fprintf(fp, "        .metadata h2 { color: #ffffff; margin-top: 0; }\n");
    fprintf(fp, "        .metadata p { margin: 5px 0; font-size: 15px; }\n");
    fprintf(fp, "        .highlight { color: #00ffcc; font-weight: bold; }\n");
    fprintf(fp, "        table { width: 100%%; border-collapse: collapse; background-color: #1e1e1e; }\n");
    fprintf(fp, "        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }\n");
    fprintf(fp, "        th { background-color: #252525; color: #00ffcc; text-transform: uppercase; letter-spacing: 1px; }\n");
    fprintf(fp, "        tr:hover { background-color: #2a2a2a; }\n");
    fprintf(fp, "        .footer { margin-top: 50px; font-size: 12px; color: #666; text-align: center; }\n");
    fprintf(fp, "    </style>\n");
    fprintf(fp, "</head>\n<body>\n");

    fprintf(fp, "    <h1>ReconX Automated Security Report (Scans %d to %d)</h1>\n", start_id, end_id);

    for (int current_id = start_id; current_id <= end_id; current_id++) {
        char query_scan[256];
        snprintf(query_scan, sizeof(query_scan), "SELECT target, scan_type, timestamp FROM scans WHERE id = %d;", current_id);

        rc = sqlite3_prepare_v2(db, query_scan, -1, &stmt_scan, NULL);
        
        if (rc != SQLITE_OK || sqlite3_step(stmt_scan) != SQLITE_ROW) {
            sqlite3_finalize(stmt_scan);
            continue; 
        }

        const unsigned char *target = sqlite3_column_text(stmt_scan, 0);
        const unsigned char *scan_type = sqlite3_column_text(stmt_scan, 1);
        const unsigned char *timestamp = sqlite3_column_text(stmt_scan, 2);

        fprintf(fp, "    <div class=\"scan-container\">\n");
        fprintf(fp, "        <div class=\"metadata\">\n");
        fprintf(fp, "            <h2>Scan ID: %d</h2>\n", current_id);
        fprintf(fp, "            <p><span class=\"highlight\">Target:</span> %s</p>\n", target);
        fprintf(fp, "            <p><span class=\"highlight\">Scan Type:</span> %s</p>\n", scan_type);
        fprintf(fp, "            <p><span class=\"highlight\">Timestamp:</span> %s</p>\n", timestamp);
        fprintf(fp, "        </div>\n");

        sqlite3_finalize(stmt_scan);

        char query_results[256];
        snprintf(query_results, sizeof(query_results), "SELECT data, extra_info FROM results WHERE scan_id = %d;", current_id);

        fprintf(fp, "        <table>\n");
        fprintf(fp, "            <thead>\n                <tr>\n                    <th>Finding / Data</th>\n                    <th>Extra Information</th>\n                </tr>\n            </thead>\n            <tbody>\n");

        rc = sqlite3_prepare_v2(db, query_results, -1, &stmt_results, NULL);
        if (rc == SQLITE_OK) {
            int count = 0;
            while (sqlite3_step(stmt_results) == SQLITE_ROW) {
                const unsigned char *data = sqlite3_column_text(stmt_results, 0);
                const unsigned char *extra_info = sqlite3_column_text(stmt_results, 1);
                const char *extra_str = (extra_info && strlen((const char*)extra_info) > 0) ? (const char*)extra_info : "N/A";

                fprintf(fp, "                <tr>\n");
                fprintf(fp, "                    <td>%s</td>\n", data);
                fprintf(fp, "                    <td>%s</td>\n", extra_str);
                fprintf(fp, "                </tr>\n");
                count++;
            }
            if (count == 0) {
                fprintf(fp, "                <tr><td colspan=\"2\" style=\"text-align: center; color: #ff4444;\">No results found for this scan.</td></tr>\n");
            }
        }
        fprintf(fp, "            </tbody>\n        </table>\n");
        fprintf(fp, "    </div>\n"); 

        sqlite3_finalize(stmt_results);
    }

    fprintf(fp, "    <div class=\"footer\">Generated by ReconX Framework - Coded in C</div>\n");
    fprintf(fp, "</body>\n</html>\n");

    fclose(fp);
    sqlite3_close(db);

    printf(GREEN "[+] Range report successfully exported to: %s\n" RESET, filename);
    return 0;
}