import os
import mimetypes

def validate_if_file_exists(data_dir, file_name):
    for root, dirs, files in os.walk(data_dir):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

def handle_get_request(data_dir, path):
    try:
        if(path == '/'):
            response_data = os.listdir(data_dir)
            file_list_str = '\n'.join(response_data)
            response = f"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(file_list_str)}\r\nContent-Disposition: inline\r\n\r\n{file_list_str}".encode("utf-8")
            return response
        else:
            file_path = validate_if_file_exists(data_dir, path[1:])
            if file_path is not None:
                content_type, _ = mimetypes.guess_type(file_path)
                if(os.path.isfile(file_path)):
                    content_type = 'text/plain'
                file_descriptor = os.open(file_path, os.O_RDONLY)
                file_d = os.read(file_descriptor, os.path.getsize(file_path))
                
                file_data = file_d.decode('utf-8')
                response = f"HTTP/1.0 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {len(file_data)}\r\nContent-Disposition: inline\r\n\r\n{file_data}".encode("utf-8")
                return response
            else:
                response = f"HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile Not Found".encode("utf-8")
                return response
    except PermissionError:
        # Handle permission-related errors
        response = f"HTTP/1.0 403.2 Read Access Forbidden\r\nContent-Length: {len('No Read Acess')}\r\nContent-Type: text/plain\r\n\r\nNo Read Acess".encode("utf-8")
        return response
        
    except Exception as e:
        # Handle other exceptions
        response = f"HTTP/1.0 404 Not Found\r\nContent-Length: {len('File Not Found')}\r\nContent-Type: text/plain\r\n\r\nFile Not Found".encode("utf-8")
        return response

def handle_file(file_path, data):
    f = open(file_path, 'wb')
    f.write(data.encode('utf-8'))
    f.close()
    response = f"HTTP/1.0 200 OK\r\nContent-Length: {len('File Created/Over-written successfully')}\r\nContent-Type: text/plain\r\n\r\nFile Created/Over-written successfully".encode("utf-8")
    return response

def handle_post_request(data_dir, path, data):
    try:
        file_path = validate_if_file_exists(data_dir, path[1:])
        if file_path is None:
            file_path = os.path.join(data_dir, path[1:])
        return handle_file(file_path, data)
    except PermissionError:
        response = f"HTTP/1.0 403.3 Write Access Forbidden\r\nContent-Length: {len('No write access')}\r\nContent-Type: text/plain\r\n\r\nNo write access".encode("utf-8")
        return response
    except Exception as e:
        response = f"HTTP/1.0 404 Not Found\r\nContent-Length: {len('File Not Found')}\r\nContent-Type: text/plain\r\n\r\nFile Not Found".encode("utf-8")
        return response
