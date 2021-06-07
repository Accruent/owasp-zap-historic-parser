"""This module is used for parsing OWASP ZAP html files and pushing the results to MySQL"""
import datetime
import mysql.connector
from lxml import etree
import pytz

# Times are stored as UTC and converted using this variable to CDT.
CENTRAL = pytz.timezone('US/Central')


def process_zap_file(opts):
    """This keyword parses the ZAP results, stores them into the appropriate tables,
        then compares the results to the most recent scan on the same environment and scan type."""
    # parse html results from Legion OWASP ZAP job
    parsed_results = html_parser(opts.filename)
    # connect to database
    my_ozhdb = connect_to_mysql_db(opts.ozh_host, opts.ozh_port, opts.ozh_username,
                                   opts.ozh_password, opts.projectname)
    root_ozhdb = connect_to_mysql_db(opts.ozh_host, opts.ozh_port, opts.ozh_username,
                                     opts.ozh_password, 'owaspzaphistoric')
    # insert latest result into tb_alerts and tb_execution, update tb_project,
    # and compare to last result
    final_message = process_zap_results(my_ozhdb, root_ozhdb, opts.this_env, opts.scantype,
                                        parsed_results, opts.projectname, opts.urllink,
                                        opts.version)
    print(final_message)
    return final_message


def html_parser(filename):
    """This keyword parses the ZAP html file."""
    # ID locators and put into list
    high_locator = "//table[@class='results']//th[contains(text(),'High ')]"
    med_locator = "//table[@class='results']//th[contains(text(),'Medium ')]"
    low_locator = "//table[@class='results']//th[contains(text(),'Low ')]"
    info_locator = "//table[@class='results']//th[contains(text(),'Informational ')]"
    loc_list = [high_locator, med_locator, low_locator, info_locator]
    zap_results = []
    # Get parser ready
    parser = etree.HTMLParser()
    tree = etree.parse(filename, parser)
    # Iterate through locators and get alert information and url count
    for loc in loc_list:
        level = ''
        loc_count = int(tree.xpath("count(" + loc + ")"))
        if loc == high_locator:
            level = 'High'
        elif loc == med_locator:
            level = 'Medium'
        elif loc == low_locator:
            level = 'Low'
        elif loc == info_locator:
            level = 'Informational'
        for i in range(loc_count):
            alert_loc = "(" + loc + ")[" + str(i + 1) + "]/../th[2]"
            alert_type = tree.xpath(alert_loc)[0]
            url_count_loc = "(" + loc + ")[" + str(i + 1) + "]/../..//td[.='URL']"
            url_count = int(tree.xpath("count(" + url_count_loc + ")"))
            this_result = [level, alert_type.text, url_count]
            if len(zap_results) == 0:
                zap_results.append(this_result)
                continue
            # if alert already exists in zap_results, then just add the URL count
            for result in zap_results:
                if level == result[0] and alert_type.text == result[1]:
                    result[2] = result[2] + url_count
                    break
                if result == zap_results[-1]:
                    zap_results.append(this_result)
                    break
    return zap_results


def process_zap_results(con, ocon, this_env, scantype, zapresults, projectname, url_link, version):
    """This keyword takes the parsed results from the ZAP file and inserts them into the
     appropriate tables."""
    cursor_obj = con.cursor()
    root_cursor_obj = ocon.cursor()
    # new row in TB_EXECUTION table
    utc = datetime.datetime.utcnow()
    cursor_obj.execute("INSERT INTO TB_EXECUTION (Execution_Id, Execution_Date) "
                       "VALUES (0, '%s')" % utc)
    con.commit()
    cursor_obj.execute("SELECT Execution_Id, Execution_Date from TB_EXECUTION ORDER BY "
                       "Execution_Id DESC LIMIT 1;")
    last_id = cursor_obj.fetchone()
    # update project's TB_ALERTS table
    for result in zapresults:
        this_level = result[0]
        this_type = result[1]
        this_urls_aff = result[2]
        sql = "INSERT INTO TB_ALERTS (Alert_Id, Execution_Id, Alert_Level, Alert_Type," \
              " URLS_Affected)" \
              "VALUES (%s, %s, %s, %s, %s);"
        val = (0, last_id[0], this_level, this_type, this_urls_aff)
        cursor_obj.execute(sql, val)
        con.commit()
    # get alert totals from TB_ALERTS for TB_EXECUTION
    cursor_obj.execute("SELECT COUNT(*) FROM TB_ALERTS WHERE Execution_Id = '%s' AND"
                       " Alert_Level ='High' ;" % last_id[0])
    high_alerts = cursor_obj.fetchone()
    cursor_obj.execute("SELECT COUNT(*) FROM TB_ALERTS WHERE Execution_Id = '%s' AND"
                       " Alert_Level ='Medium' ;" % last_id[0])
    medium_alerts = cursor_obj.fetchone()
    cursor_obj.execute("SELECT COUNT(*) FROM TB_ALERTS WHERE Execution_Id = '%s' AND"
                       " Alert_Level ='Low' ;" % last_id[0])
    low_alerts = cursor_obj.fetchone()
    cursor_obj.execute("SELECT COUNT(*) FROM TB_ALERTS WHERE Execution_Id = '%s' AND"
                       " Alert_Level ='Informational' ;" % last_id[0])
    info_alerts = cursor_obj.fetchone()
    # update project's TB_EXECUTION latest id
    cursor_obj.execute("UPDATE TB_EXECUTION SET Environment = '%s', Scan_Type = '%s',"
                       "High_Alerts = %s, Medium_Alerts = %s,"
                       "Low_Alerts = %s, Informational_Alerts = %s, URL_Link = '%s', "
                       "Version = '%s' WHERE Execution_Id='%s';"
                       % (this_env, scantype, high_alerts[0], medium_alerts[0], low_alerts[0],
                          info_alerts[0], url_link, version, last_id[0]))
    con.commit()
    # update owasphistoric.TB_PROJECT table
    cursor_obj.execute("SELECT COUNT(*) FROM TB_EXECUTION;")
    execution_rows = cursor_obj.fetchone()
    root_cursor_obj.execute(
        "UPDATE TB_PROJECT SET Last_Updated = '%s', Total_Executions = %s, Environment = '%s',"
        "Scan_Type ='%s', Recent_High =%s, Recent_Medium =%s, Recent_Low =%s, "
        "Recent_Informational =%s, Version ='%s' WHERE Project_Name='%s';"
        % (utc, execution_rows[0], this_env, scantype, high_alerts[0], medium_alerts[0],
           low_alerts[0], info_alerts[0], version, projectname))
    ocon.commit()
    last_date = last_id[1].replace(tzinfo=datetime.timezone.utc)\
        .astimezone(CENTRAL).strftime('%b %d %Y %I:%M %p %Z')
    # compare latest results
    # Construct title for email body
    title = "<h1>OWASP ZAP Report Comparison for " + this_env + " / " + scantype + " / " +\
            version + "</h1><hr /><table style='border: 1px white; border-collapse: collapse;'>" +\
            "<thead>" + "</thead><tbody><tr><td style='border: 1px;'><strong>This report date: " +\
            "</strong></td>" + "<td style='border: 1px;'>" + last_date + "</td></tr><tr>" +\
            "<td style='border: 1px;'>" + "<strong>This report link:</strong></td><td style" +\
            "='border: 1px;'><a href='" + url_link.replace(' ', '%20') + "'>This ZAP Report" +\
            "</a></td></tr>"
    overall = ""
    alert_breakdown = ""
    cursor_obj.execute("SELECT COUNT(*) FROM TB_EXECUTION WHERE Environment = '%s'"
                       " AND Scan_Type ='%s' ;" % (this_env, scantype))
    compare_rows = cursor_obj.fetchone()
    if compare_rows[0] < 2:
        title += "</tbody></table><p>Not enough rows to compare results for " + this_env +\
                 " and " + scantype + ".</p><hr />"
    else:
        cursor_obj.execute("SELECT Execution_Id, Execution_Date, URL_Link FROM TB_EXECUTION "
                           "WHERE Environment = '%s' AND Scan_Type ='%s' ORDER BY Execution_Id "
                           "DESC LIMIT 2;" % (this_env, scantype))
        these_rows = cursor_obj.fetchall()
        compare_row = these_rows[1]
        cursor_obj.execute("SELECT Alert_level, Alert_Type, URLS_Affected FROM TB_ALERTS WHERE "
                           "Execution_Id = '%s'" % last_id[0])
        current_alerts = cursor_obj.fetchall()
        cursor_obj.execute("SELECT Alert_level, Alert_Type, URLS_Affected FROM TB_ALERTS WHERE "
                           "Execution_Id = '%s'" % compare_row[0])
        last_alerts = cursor_obj.fetchall()
        cursor_obj.execute("SELECT Version FROM TB_EXECUTION WHERE Execution_Id = '%s'"
                           % compare_row[0])
        last_version = cursor_obj.fetchone()
        compare_date = compare_row[1].replace(tzinfo=datetime.timezone.utc)\
            .astimezone(CENTRAL).strftime('%b %d %Y %I:%M %p %Z')
        title += "<tr><td style='border: 1px;'><strong>Comparison Report Version:</strong></td>" +\
                 "<td style='border: 1px;'>" + str(last_version[0]) + "</td></tr><tr>" + \
                 "<td style='border: 1px;'><strong>Comparison Report Date:</strong></td>" + \
                 "<td style='border: 1px;'>" + compare_date + "</td></tr><tr>" + \
                 "<td style='border: 1px;'><strong>Comparison Report Link:</strong></td>" + \
                 "<td style='border: 1px;'><a href='" + compare_row[2].replace(' ', '%20') + "'>" +\
                 "Comparison ZAP Report</a></td></tr></tbody></table><hr />"
        # Construct Overall Alerts Table
        total_alerts = high_alerts[0] + medium_alerts[0] + low_alerts[0] + info_alerts[0]
        overall = "<h2>Overall Alerts</h2><table style='float: left; text-align: center; " + \
                  "border: 1px white; border-collapse: collapse;' width='465'><thead><tr " + \
                  "style='background: gray;'><td style='border: 1px solid;'><strong>Total" + \
                  "</strong></td><td style='border: 1px solid;'><strong>High</strong></td>" + \
                  "<td style='border: 1px solid;'><strong>Medium</strong></td><td style='" + \
                  "border: 1px solid;'><strong>Low</strong></td><td style='border: 1px solid;'>" + \
                  "<strong>Informational</strong></td></tr></thead><tbody><tr style='" + \
                  "background: silver;'><td style='border: 1px solid;'><strong>" + \
                  str(total_alerts) + "</strong></td><td style='border: 1px solid black; " + \
                  "color: red;'><strong>" + str(high_alerts[0]) + "</strong></td><td style='" + \
                  "border: 1px solid black; color: #f6821f;'><strong>" + str(medium_alerts[0]) + \
                  "</strong></td><td style='border: 1px solid black; color: #ffff66;'><strong>" + \
                  str(low_alerts[0]) + "</strong></td><td style='border: 1px solid;'><strong>" + \
                  str(info_alerts[0]) + "</strong></td></tr></tbody></table><br><br><br><hr />"
        current_dict = convert_alert_to_dictionary(current_alerts)
        last_dict = convert_alert_to_dictionary(last_alerts)
        alert_breakdown = compare_zap_results(current_dict, last_dict, last_date,
                                              compare_date)
    html_message = title + overall + alert_breakdown
    return html_message


def convert_alert_to_dictionary(alert_list):
    """This method converts a list of tuples into a dictionary of dictionaries"""
    overall_dict = {}
    for level, alert_type, count in alert_list:
        combine = level + " | " + alert_type
        this_dict = {combine: {'Alert Level': level,
                               'Alert Type': alert_type,
                               'URLs Affected': count}}
        overall_dict.update(this_dict)
    return overall_dict


def compare_zap_results(set1, set2, date1, date2):
    """This keyword compares the current ZAP result with the most recent result of the same
    parameters and creates a table showing the differences."""
    # Set H2 and Table Headers
    alerts_table = "<h2>Alert Breakdown</h2><table style='float: left; text-align: center; " + \
                   "border: 1px white; border-collapse: collapse;' width='1400'><thead>" + \
                   "<tr style='background: gray;'><td style='border: 1px solid;'><strong>" + \
                   "Alert Level</strong></td><td style='border: 1px solid;'><strong>Description" + \
                   "</strong></td><td style='border: 1px solid;'><strong>URLs Affected<br />" + \
                   date1 + "</strong></td><td style='border: 1px solid;'><strong>URLs " +\
                   "Affected<br />" + date2 + "</strong></td><td style='border: 1px solid" +\
                   ";'><strong>Comments</strong></td></tr></thead><tbody>"
    # Set Alert Table
    high_alerts = ''
    low_alerts = ''
    med_alerts = ''
    info_alerts = ''
    resolved_alerts = ''
    for key in set1:
        if key in set2:
            if set2[key]['Alert Level'] == "High":
                high_alerts += get_alert_table_row("#ff8585", "High", set1[key]['Alert Type'],
                                                   set1[key]['URLs Affected'],
                                                   set2[key]['URLs Affected'])
            elif set2[key]['Alert Level'] == "Medium":

                med_alerts += get_alert_table_row("orange", "Medium", set1[key]['Alert Type'],
                                                  set1[key]['URLs Affected'],
                                                  set2[key]['URLs Affected'])
            elif set2[key]['Alert Level'] == "Low":
                low_alerts += get_alert_table_row("lightyellow", "Low", set1[key]['Alert Type'],
                                                  set1[key]['URLs Affected'],
                                                  set2[key]['URLs Affected'])
            else:
                info_alerts += get_alert_table_row("silver", "Informational",
                                                   set1[key]['Alert Type'],
                                                   set1[key]['URLs Affected'],
                                                   set2[key]['URLs Affected'])
        else:
            if set1[key]['Alert Level'] == "High":
                high_alerts += get_alert_table_row("#ff8585", "High", set1[key]['Alert Type'],
                                                   set1[key]['URLs Affected'], 0)
            elif set1[key]['Alert Level'] == "Medium":
                med_alerts += get_alert_table_row("orange", "Medium", set1[key]['Alert Type'],
                                                  set1[key]['URLs Affected'], 0)
            elif set1[key]['Alert Level'] == "Low":
                low_alerts += get_alert_table_row("lightyellow", "Low", set1[key]['Alert Type'],
                                                  set1[key]['URLs Affected'], 0)
            else:
                info_alerts += get_alert_table_row("silver", "Informational",
                                                   set1[key]['Alert Type'],
                                                   set1[key]['URLs Affected'], 0)
    for key in set2:
        if key not in set1:
            resolved_alerts += get_alert_table_row("lightgreen", set2[key]['Alert Level'],
                                                   set2[key]['Alert Type'],
                                                   0, set2[key]['URLs Affected'])
    # Construct and close Alerts table
    alerts_table += high_alerts + med_alerts + low_alerts + info_alerts + \
        resolved_alerts + "</tbody></table>"
    return alerts_table


def get_alert_table_row(back_color, alert_type, desc, urls, urls2):
    """This method creates a table row for the alert table."""
    comments = ''
    if urls > urls2 > 0:
        comments = 'Number of URLs Affected increased'
    elif urls2 > urls > 0:
        comments = 'Number of URLs Affected decreased'
    elif urls == urls2 != 0:
        comments = 'Number of URLs Affected stayed the same'
    elif urls == 0:
        comments = 'Alert potentially resolved'
    elif urls2 == 0:
        comments = 'New Alert'
    this_table_row = "<tr style='background: " + back_color + ";'><td style='border: 1px solid" +\
                     ";'><strong>" + alert_type + "</strong></td><td style='border: 1px " +\
                     "solid;'><strong>" + desc + "</strong></td><td style=' border: 1px solid;'>" +\
                     "<strong>" + str(urls) + "</strong>" + "</td><td style='border: 1px solid" +\
                     ";'><strong>" + str(urls2) + "</strong></td><td style='border: 1px solid;'>" +\
                     "<strong>" + comments + "</strong></td></tr>"
    return this_table_row


def connect_to_mysql_db(host, port, user, pwd, dbname):
    """This keyword makes the connection to the MySQL database."""
    try:
        mydb = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            passwd=pwd,
            database=dbname
        )
        return mydb
    except AttributeError:
        print('Unable to make MySQL connection')
