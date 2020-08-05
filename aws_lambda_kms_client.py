import json
import boto3
import os

def lambda_handler(event, context):
    status_code = 200
    client = boto3.client('kms')
    array_of_rows_to_return = [ ]
    try:
        event_body = event["body"]
        payload = json.loads(event_body)
        rows = payload["data"]
        row = rows[0]
        row_number = row[0]
        rootban = row[1] 
        opcode = row[2] 
        keyId = os.environ['CMK'] 
        
        if opcode == 'CREATE':
            response = client.generate_data_key(
                KeyId=keyId, 
                EncryptionContext={'rootban': rootban},
                KeySpec='AES_256'
            )
            print("> Create OK")
            
        if opcode == 'DECODE':
            RB = rootban.split(':::')
            blob = bytes.fromhex(RB[1])
            print(blob)
            ban = RB[0]
            response = client.decrypt(
                CiphertextBlob=blob,
                EncryptionContext={
                    'rootban': ban
                },
                KeyId=keyId
            )
            print("> Decode OK")

        output_value = [rootban, response["KeyId"], response["Plaintext"].hex(), response["CiphertextBlob"].hex()]
        row_to_return = [row_number, output_value]
        array_of_rows_to_return.append(row_to_return)

        json_compatible_string_to_return = json.dumps({"data" : array_of_rows_to_return})
        print(json_compatible_string_to_return)

    except Exception as err:
        # 400 implies some type of error.
        status_code = 400
        print("> Error " + err.__str__())
        json_compatible_string_to_return = event_body

    # Return the return value and HTTP status code.
    return {
        'statusCode': status_code,
        'body': json_compatible_string_to_return
    }
