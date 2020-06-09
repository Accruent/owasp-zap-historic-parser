"""This module is used for parsing OWASP ZAP html files and pushing the results to MySQL"""
# import sys
import mysql.connector
from lxml import etree


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
    cursor_obj.execute("INSERT INTO TB_EXECUTION (Execution_Id, Execution_Date) VALUES (0, now())")
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
        "UPDATE TB_PROJECT SET Last_Updated = now(), Total_Executions = %s, Environment = '%s',"
        "Scan_Type ='%s', Recent_High =%s, Recent_Medium =%s, Recent_Low =%s, "
        "Recent_Informational =%s, Version ='%s' WHERE Project_Name='%s';"
        % (execution_rows[0], this_env, scantype, high_alerts[0], medium_alerts[0], low_alerts[0],
           info_alerts[0], version, projectname))
    ocon.commit()
    # compare latest results
    message = "OWASP ZAP Report comparison for " + this_env + " / " + scantype + " / " + version +\
              "\n" + "This report date: " + str(last_id[1]) + "\n" + "This report link: " +\
              url_link.replace(' ', '%20') + "\n"
    cursor_obj.execute("SELECT COUNT(*) FROM TB_EXECUTION WHERE Environment = '%s'"
                       " AND Scan_Type ='%s' ;" % (this_env, scantype))
    compare_rows = cursor_obj.fetchone()
    if compare_rows[0] < 2:
        message += 'Not enough rows to compare results for ' + this_env + ' and ' + scantype + '.'
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
        message += "Comparison report version: " + str(last_version[0]) + "\n" + "Comparison " \
                   "report date: " + str(compare_row[1]) + "\n" + "Comparison report link: " + \
                   compare_row[2].replace(' ', '%20') + "\n" + "\n" + \
                   compare_zap_results(current_alerts, last_alerts)
    html_message = "<p>" + message.replace("\n", "<br>") + "</p>"
    return html_message


def compare_zap_results(set1, set2):
    """This keyword compares the current ZAP result with the most recent result of the same
    parameters and creates a message showing the differences."""
    this_message = ''
    same_message = ''
    diff_message = ''
    new_message = ''
    resolved_message = ''
    if len(set1) != len(set2):
        this_message += "The number of alerts in the this result and the most recent result " \
                        "do not match - " + str(len(set1)) + " != " + str(len(set2)) + '\n'
    for alert in set1:
        if alert in set2:
            same_message += "Alert Level: " + str(alert[0]) + " | Alert Type: " + str(alert[1])\
                            + " | URLS Affected: " + str(alert[2]) + " is the same in both " \
                            "result sets. \n"
            set1.remove(alert)
            set2.remove(alert)
        else:
            for atype, desc, urls in [alert[0:3]]:
                alert2 = ''
                for alert2 in set2:
                    for atype2, desc2, urls2 in [alert2[0:3]]:
                        if atype == atype2 and desc == desc2:
                            if urls > urls2:
                                diff = urls - urls2
                                diff_message += "Number of URLS for " + atype + " | " + desc + \
                                                " increased by " + str(diff) + ".\n" + "This " \
                                                "report URLS affected: " + str(urls) + " / " + \
                                                "Comparison report URLS affected: " + str(urls2)\
                                                + "\n"
                            else:
                                diff = urls2 - urls
                                diff_message += "Number of URLS for " + desc + " decreased by "\
                                                + str(diff) + ".\n" + "This report URLS " \
                                                "affected: " + str(urls) + " / Comparison " \
                                                "report URLS affected: " + str(urls2) + "\n"
                            set1.remove(alert)
                            set2.remove(alert2)
                            break
                    else:
                        continue
                    break
                if alert2 == set2[-1]:
                    new_message += "NEW ALERT - Alert Level: " + str(alert[0]) + " | Alert " \
                                    "Type: " + str(alert[1]) + " | URLS Affected: " + \
                                   str(alert[2]) + " not found in most recent result.\n"
                    set1.remove(alert)
                    break
    for alert in set2:
        if alert not in set1:
            resolved_message += "ALERT POTENTIALLY RESOLVED - Alert Level: " + str(alert[0]) + \
                                " | Alert Type: " + str(alert[1]) + " | URLS Affected: " +\
                                str(alert[2]) + " from recent result not found in this result.\n"
    this_message += new_message + resolved_message + diff_message + same_message
    return this_message


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


# FILENAME = sys.argv[1]
# PROJECT_NAME = sys.argv[2]
# THIS_ENV = sys.argv[3]
# SCAN_TYPE = sys.argv[4]
# URL_LINK = sys.argv[5]
# OZH_HOST = sys.argv[6]
# OZH_PORT = sys.argv[7]
# OZH_USERNAME = sys.argv[8]
# OZH_PASSWORD = sys.argv[9]
# VERSION = sys.argv[10]
#
# process_zap_file(FILENAME, PROJECT_NAME, THIS_ENV, SCAN_TYPE, URL_LINK, OZH_HOST, OZH_PORT,
#                  OZH_USERNAME, OZH_PASSWORD, VERSION)
#

# LOCAL TESTING AREA
# html = process_zap_file('c:\\temp\\report_229_.html', 'test', 'qa03', 'passive',
#                          'http://www.google.com'
#                          'ZAP_20scanning_20report/',
#                          'localhost', 3306, 'superuser', 'passw0rd', 'test_version3')
# print(html)
