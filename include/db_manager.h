#ifndef DB_MANAGER_H
#define DB_MANAGER_H

#include <sqlite3.h>

int init_database();
int create_new_scan(const char* target, const char* scan_type, char* timestamp);
int save_scan_result(int scan_id, const char* data, const char* extra_info);
int show_data(int id, char* table_name);
int print_callback(void *data, int argc, char **argv, char **azColName);
int show_scan_report(int scan_id);
int show_scan_history();
void reset_database();

#endif // DB_MANAGER_H