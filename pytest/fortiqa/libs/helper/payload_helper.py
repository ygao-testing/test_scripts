       

def payload_helper(alert_name, status, start_time, end_time):
    """
    generate payload for query alerts with custom filters
    
    Args:
        alert_name(str): alert name to filter
        status(str): alert status to filter
        start_time (int): Start timestamp to filter time range
        end_time (int): End timestamp  to filter time range
    
    Returns:
        dict: Query payload
    """
    
    payload = {
        "Filters": {
            "AlertMetadataFilters.NAME": [
                {
                    "filterGroup": "Matches",
                    "value": alert_name
                }
            ],
            "AlertMetadataFilters.STATUS":[
                {
                    "filterGroup":"Includes",
                    "value": status
                }
            ]#,
            # "AWS_CIS_Filters.ACCOUNT_ID": [
            #     {
            #         "filterGroup": "include",
            #         "value": aws_account.aws_account_id
            #     }
            # ]
        },
        "OrderBy": {
            "field": "START_TIME",
            "order": "Desc"
        },
        "ParamInfo": {
            "StartTimeRange": start_time,
            "EndTimeRange": end_time
        }
    }
    return payload

    