import dtc_utils
import ecu_config as ecu_config
from loggers.logger_app import logger
import secrets  # For generating cryptographic secure challenge
import hashlib  # For hashing challenge and response


DIAGNOSTIC_SESSION_CONTROL_SID = 0x10
SECURITY_ACCESS_SID = 0x27
SECURITY_ACCESS_LEVEL_1 = 0x01  # Seed Request
SECURITY_ACCESS_LEVEL_2 = 0x02  # Key Send
SECURITY_ACCESS_ATTEMPT_LIMIT = 3

DIAGNOSTIC_SESSION_TYPES = [0x01, 0x02, 0x03, 0x04]

DIAGNOSTIC_SESSION_PARAMETER_RECORD = [0x00, 0x1E, 0x0B, 0xB8]

ECU_RESET_SID = 0x11

ECU_RESET_ENABLE_RAPID_POWER_SHUT_DOWN = 0x04

ECU_RESET_POWER_DOWN_TIME = 0x0F

READ_DTC_INFO_BY_STATUS_MASK = 0x2

READ_DTC_INFO_SID = 0x19

READ_DTC_STATUS_AVAILABILITY_MASK = 0xFF

DTCS = dtc_utils.encode_uds_dtcs(ecu_config.get_dtcs())

POSITIVE_RESPONSE_SID_MASK = 0x40

NEGATIVE_RESPONSE_SID = 0x7F

NRC_SUB_FUNCTION_NOT_SUPPORTED = 0x12

NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = 0x13

REQUEST_DOWNLOAD_SID = 0x34

REQUEST_UPLOAD_SID = 0x35

TRANSFER_DATA_SID = 0x36

REQUEST_TRANSFER_EXIT_SID = 0x37

NRC_REQUEST_OUT_OF_RANGE = 0x31

NRC_SECURITY_ACCESS_DENIED = 0x33

NRC_INCORRECT_MESSAGE_LENGTH = 0x13

NRC_REQUEST_OUT_OF_RANGE = 0x31

NRC_SECURITY_ACCESS_DENIED = 0x33

NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = 0x13

NRC_CONDITIONS_NOT_CORRECT = 0x22

# State for security access
security_attempts = 0
security_challenge = None
SECURITY_KEY = b'MkEcS7dCTT3ur8iRYbpRhAa9uxb7Q4vl'  # Secret key for hashing challenge (in a real system, this would be securely stored)
is_ecu_unlocked = False  # Replace with real security check logic
ecu_memory_address = None
ecu_data_length = None
global_buffer = b''
is_upload = False  # False for download, True for upload
MAX_NUMBER_OF_BLOCK_LENGTH = 0x0FFA

SERVICES = [
    {"id": ECU_RESET_SID, "description": "ECUReset", "response": lambda request: get_0x11_response(request)},
    {"id": READ_DTC_INFO_SID, "description": "ReadDTCInformation", "response": lambda request: get_0x19_response(request)},
    {"id": DIAGNOSTIC_SESSION_CONTROL_SID, "description": "DiagnosticSessionControl", "response": lambda request: get_0x10_response(request)},
    {"id": REQUEST_DOWNLOAD_SID, "description": "RequestDownload", "response": lambda request: get_0x34_response(request)},
    {"id": REQUEST_UPLOAD_SID, "description": "RequestUpload", "response": lambda request: get_0x35_response(request)},
    {"id": TRANSFER_DATA_SID, "description": "TransferData", "response": lambda request: get_0x36_response(request)},
    {"id": REQUEST_TRANSFER_EXIT_SID, "description": "RequestTransferExit", "response": lambda request: get_0x37_response(request)},
    {"id": SECURITY_ACCESS_SID, "description": "SecurityAccess", "response": lambda request: get_0x27_response(request)},
]


with open("uds/services.py", "rb") as f:
    firmware = f.read()


ecu_memory = {"0x40000000": firmware}

def process_service_request(request):
    if request is not None and len(request) >= 1:
        sid = request[0]
        for service in SERVICES:
            if service.get("id") == sid:
                logger.info("Requested UDS SID " + hex(sid) + ": " + service.get("description"))
                return service.get("response")(request)
        logger.warning("Requested SID " + hex(sid) + " not supported")
    else:
        logger.warning("Invalid request")
        return None


def get_0x10_response(request):
    if len(request) == 2:
        session_type = request[1]
        if session_type in DIAGNOSTIC_SESSION_TYPES:
            return get_positive_response_sid(DIAGNOSTIC_SESSION_CONTROL_SID) + bytes([session_type]) \
                   + bytes(DIAGNOSTIC_SESSION_PARAMETER_RECORD)
        return get_negative_response(DIAGNOSTIC_SESSION_CONTROL_SID,  NRC_SUB_FUNCTION_NOT_SUPPORTED)
    return get_negative_response(DIAGNOSTIC_SESSION_CONTROL_SID,  NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)


def get_0x11_response(request):
    if len(request) == 2:
        reset_type = request[1]
        if is_reset_type_supported(reset_type):
            positive_response = get_positive_response_sid(ECU_RESET_SID) + bytes([reset_type])
            if reset_type == ECU_RESET_ENABLE_RAPID_POWER_SHUT_DOWN:
                return positive_response + bytes([ECU_RESET_POWER_DOWN_TIME])
            return positive_response
        return get_negative_response(ECU_RESET_SID,  NRC_SUB_FUNCTION_NOT_SUPPORTED)
    return get_negative_response(ECU_RESET_SID,  NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)


def get_0x19_response(request):
    if len(request) == 2:
        report_type = request[1]
        if report_type == READ_DTC_INFO_BY_STATUS_MASK:
            positive_response = get_positive_response_sid(READ_DTC_INFO_SID) + bytes([report_type]) \
                                + bytes([READ_DTC_STATUS_AVAILABILITY_MASK])
            return add_dtcs_to_response(positive_response)
        return get_negative_response(READ_DTC_INFO_SID, NRC_SUB_FUNCTION_NOT_SUPPORTED)
    return get_negative_response(READ_DTC_INFO_SID, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

def get_0x27_response(request):
    global security_attempts, security_challenge, is_ecu_unlocked
    if len(request) >= 2:
        access_type = request[1]
        if access_type == SECURITY_ACCESS_LEVEL_1:  # Seed request
            security_challenge = secrets.token_bytes(4)  # Generate a 4-byte challenge
            security_attempts = 0
            logger.info("Generated security challenge for level 1")
            return get_positive_response_sid(SECURITY_ACCESS_SID) + bytes([access_type]) + security_challenge
        elif access_type == SECURITY_ACCESS_LEVEL_2:  # Key submission
            if security_attempts < SECURITY_ACCESS_ATTEMPT_LIMIT:
                if validate_security_response(request[2:]):  # Validate challenge response
                    logger.info("Security access granted")
                    is_ecu_unlocked = True
                    return get_positive_response_sid(SECURITY_ACCESS_SID) + bytes([access_type])
                else:
                    security_attempts += 1
                    logger.warning("Incorrect security response attempt " + str(security_attempts))
            if security_attempts >= SECURITY_ACCESS_ATTEMPT_LIMIT:
                return get_negative_response(SECURITY_ACCESS_SID, NRC_SECURITY_ACCESS_DENIED)
            return get_negative_response(SECURITY_ACCESS_SID, NRC_SUB_FUNCTION_NOT_SUPPORTED)
    return get_negative_response(SECURITY_ACCESS_SID, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)


def validate_security_response(response):
    if security_challenge:
        expected_response = hashlib.sha256(security_challenge + SECURITY_KEY).digest()[:4]  # Get first 4 bytes
        print(f"expected_response: {expected_response}")
        return expected_response == response
    return False


# Request Download (0x34) - initialize download session to ECU
def get_0x34_response(request):
    global is_ecu_unlocked, ecu_memory_address, ecu_data_length, global_buffer, is_upload, ecu_memory
    is_upload = False  # Download mode
    
    if not is_ecu_unlocked:
        return get_negative_response(REQUEST_DOWNLOAD_SID, NRC_SECURITY_ACCESS_DENIED)

    # Check request length
    if len(request) < 8:
        return get_negative_response(REQUEST_DOWNLOAD_SID, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

    # Parse memory address and data length for download
    ecu_memory_address = int.from_bytes(request[3:7], 'big')
    ecu_data_length = int.from_bytes(request[7:11], 'big')
    global_buffer = b''
    ecu_memory[hex(ecu_memory_address)] = b''
    print("Request Download: Address =", hex(ecu_memory_address), "Length =", ecu_data_length)
    
    # Return a positive response with the maximum block size
    max_block_size = 64  # Example block size for data transfer
    return bytes([0x74, max_block_size >> 8, max_block_size & 0xFF])

# Request Upload (0x35) - initialize upload session from ECU
def get_0x35_response(request):
    global ecu_memory_address, ecu_data_length, is_upload, global_buffer
    is_upload = True  # Upload mode

    # Check request length
    if len(request) < 8:
        return get_negative_response(REQUEST_UPLOAD_SID, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

    # Parse memory address and data length for upload
    ecu_memory_address = int.from_bytes(request[3:7], 'big')
    ecu_data_length = int.from_bytes(request[7:11], 'big')
    global_buffer = b'' 
    print("Request Upload: Address =", hex(ecu_memory_address), "Length =", ecu_data_length)
    
    # Return a positive response with maximum block size
    max_block_size = 64  # Example block size for data transfer
    return bytes([0x75, max_block_size >> 8, max_block_size & 0xFF])

# Transfer Data (0x36) - handle data blocks for both upload and download
def get_0x36_response(request):
    global global_buffer, ecu_data_length

    # Validate message length
    if len(request) < 2:
        return get_negative_response(TRANSFER_DATA_SID, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

    # Check if ECU is ready to transfer data
    if ecu_data_length is None or ecu_memory_address is None:
        return get_negative_response(TRANSFER_DATA_SID, NRC_CONDITIONS_NOT_CORRECT)

    # If upload, send data to the client
    if is_upload:
        # Simulate sending data from ECU to client
        transfered_len = len(global_buffer)
        data_block = ecu_memory[hex(ecu_memory_address)][transfered_len:transfered_len+min(64, ecu_data_length - transfered_len)]
        global_buffer += data_block
        print("Transferring data block to client:", data_block.hex())
        return bytes([0x76]) + data_block  # Positive response for upload

    # If download, receive data from the client
    else:
        data_chunk = request[1:]  # Extract data payload from request
        global_buffer += data_chunk
        print("Received data block:", data_chunk.hex())

        # Check if all data has been received
        if len(global_buffer) >= ecu_data_length:
            print("All data received successfully for download.")

        return get_positive_response_sid(TRANSFER_DATA_SID)

# Request Transfer Exit (0x37) - finalize transfer for both upload and download
def get_0x37_response(request):
    global ecu_memory_address, ecu_data_length, global_buffer, is_upload, ecu_memory

    # Check if data transfer session is valid
    if ecu_data_length is None or ecu_memory_address is None:
        return get_negative_response(REQUEST_TRANSFER_EXIT_SID, NRC_CONDITIONS_NOT_CORRECT)

    # If download, finalize the data write
    if not is_upload:
        # Check if all data has been received
        if len(global_buffer) < ecu_data_length:
            return get_negative_response(REQUEST_TRANSFER_EXIT_SID, NRC_CONDITIONS_NOT_CORRECT)
        
        # Simulate writing received data to ECU memory
        print("Data transfer completed. Data written to memory address:", hex(ecu_memory_address))
        with open("firmware.bin", "wb") as f:
            f.write(global_buffer)
        ecu_memory[hex(ecu_memory_address)] = global_buffer
    # If upload, simply confirm the end of the session
    else:
        print("Upload session completed, data retrieved from ECU.")
    
    # Reset ECU state
    ecu_memory_address = None
    ecu_data_length = None
    global_buffer = b''

    return get_positive_response_sid(REQUEST_TRANSFER_EXIT_SID)

def is_reset_type_supported(reset_type):
    return 0x05 >= reset_type >= 0x01


def add_dtcs_to_response(response):
    if len(DTCS) > 0:
        return response + DTCS
    return response


def get_positive_response_sid(requested_sid):
    return bytes([requested_sid + POSITIVE_RESPONSE_SID_MASK])


def get_negative_response(sid, nrc):
    logger.warning("Negative response for SID " + hex(sid) + " will be sent")
    return bytes([NEGATIVE_RESPONSE_SID]) + bytes([sid]) + bytes([nrc])