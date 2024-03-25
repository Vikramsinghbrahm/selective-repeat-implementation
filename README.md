# Selective Repeat Protocol Implementation
## Overview
This project implements the selective repeat protocol for reliable data transmission over a network using UDP. The selective repeat protocol is a sliding window protocol that allows the sender to send multiple packets before receiving an acknowledgment for each one. This improves network efficiency by minimizing the number of retransmissions.

## Features
1. Selective Repeat Protocol Implementation
- Reliable Data Transmission: Implements the selective repeat protocol, a sliding window protocol that ensures reliable data transmission over a network.
- Packet Retransmission: Handles packet retransmission for packets that are not acknowledged within a specified timeout period, ensuring data integrity.
- Selective Repeat Strategy: Utilizes a selective repeat strategy to resend only those packets that have not been acknowledged by the receiver, optimizing network efficiency.
2. Threading for Concurrent Execution
- Concurrency with Threading: Utilizes threading to enable concurrent execution of various tasks, such as sending data packets, monitoring for timeouts, and receiving acknowledgments.
- Improved Performance: Enhances performance by allowing multiple tasks to execute concurrently without blocking each other, leading to efficient utilization of system resources.
3. Robust Error Handling
- Packet Loss Mitigation: Implements robust error handling mechanisms to mitigate the effects of packet loss during transmission, ensuring reliable data delivery even in the presence of network disruptions.
- Out-of-Order Delivery Handling: Handles out-of-order packet delivery by maintaining a buffer to reorder received packets before processing them, maintaining data integrity.
- Timeout Handling: Monitors for packet timeouts and initiates appropriate actions, such as packet retransmission, to recover from network delays or unresponsive receivers.
4. Integration with File Server Application
- Seamless File Transfer: Seamlessly integrates with a file server application to facilitate reliable file transfer over the network using the selective repeat protocol.
- GET Request Support: Supports GET requests to retrieve files from the server, ensuring accurate and efficient data retrieval.
- POST Request Support: Supports POST requests to upload files to the server, providing a reliable mechanism for data transmission and storage.
5. Customizable Network Configuration
- Router Configuration: Allows configuration of router parameters such as port number, drop rate, maximum delay, and seed value, providing flexibility in simulating various network conditions.
- Server Configuration: Enables configuration of server parameters such as port number and verbosity level, allowing customization based on specific requirements.
6. Detailed Logging and Debugging
- Verbose Output: Provides verbose output during execution to facilitate debugging and troubleshooting, offering detailed insights into the protocol operation and network interactions.
- Logging Mechanism: Implements a logging mechanism to record key events, packet transmissions, timeouts, and acknowledgments, aiding in post-mortem analysis and performance optimization.

## Usage
To use the project, follow these steps:

1. Start the router:
```bash
   ./router.exe --port 3000 --drop-rate 0.3 --max-delay 100ms --seed 1
```
2. Start the HTTP file server:
```bash
   ./httpfs -v -p 8007
```
3. Perform a GET request:
```bash
   ./httpc get --serverhost 'http://localhost/sample.txt' --serverport 8007 --routerhost localhost --routerport 3000
```

4. Perform a POST request:
```bash
   ./httpc post -v --serverhost 'http://localhost/sample3.txt' --d your_file_path.txt --serverport 8007 --routerhost localhost --routerport 3000
```

Replace `'your_file_path.txt'` with the path to the file you want to upload in the POST request.

## Dependencies
- Python 3.x

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
