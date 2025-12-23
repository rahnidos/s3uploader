# OCI Bucket Uploader

This project is a Flask application that allows users to upload files to Oracle Cloud Infrastructure (OCI) Object Storage. It provides a simple web interface for file uploads and handles authentication through a password.

## Features

- Upload files to OCI Object Storage.
- Password protection for file uploads.
- Simple web interface for easy file selection and upload.
- IP blocking functionality.

## Requirements

- Python 3.x
- Flask
- OCI SDK (oci)

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/oci-uploader.git
   cd oci-uploader
   ```

2. Create a virtual environment (optional but recommended):

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the root directory based on .env.example



## Running the Application

To run the application locally, use the following command:

```
python app.py
```

The application will be available at `http://localhost:5000`.


## Contributing

Feel free to submit issues or pull requests for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.