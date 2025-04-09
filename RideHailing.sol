// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract RideHailing is Ownable {
    // Struct to store driver details
    struct Driver {
        string vehicleOwnerName;    // max 100 chars
        string dateOfBirth;         // YYYY-MM-DD (10 chars)
        string gender;              // max 10 chars
        string cnic;                // 15 chars (12345-6789012-3)
        string contactNumber;       // 12 chars (0300-1234567)
        string email;               // max 100 chars
        bytes32 passwordHash;
        string licenseNumber;       // max 15 chars (ABC-1234567)
        string vehicleRegNumber;    // max 20 chars
        string vehicleType;         // max 20 chars
        string addressDetails;      // max 200 chars
        string profilePictureCID;   // IPFS CID
        string vehiclePictureCID;   // IPFS CID
        bool isRegistered;
    }

    // Struct to group registration parameters
    struct RegistrationParams {
        string vehicleOwnerName;
        string dateOfBirth;
        string gender;
        string cnic;
        string contactNumber;
        string email;
        string licenseNumber;
        string vehicleRegNumber;
        string vehicleType;
        string addressDetails;
        bytes32 passwordHash;
        string profilePictureCID;
        string vehiclePictureCID;
    }

    // Mappings
    mapping(address => Driver) public drivers;
    mapping(string => address) public emailToAddress;

    // Arrays
    address[] public registeredDrivers;

    // Events
    event DriverRegistered(address indexed driverAddress, string email);
    event DriverStatusChanged(address indexed driverAddress, bool status);
    event ProfileUpdated(address indexed driverAddress, string profilePictureCID);
    event VehicleUpdated(address indexed driverAddress, string vehiclePictureCID);

    // Modifier to check if driver is registered
    modifier onlyRegisteredDriver() {
        require(drivers[msg.sender].isRegistered, "Driver not registered");
        _;
    }

    /**
     * @dev Registers a new driver with strict input validation
     * @param params A struct containing all registration parameters
     */
    function registerDriver(RegistrationParams memory params) public {
        // Validate input data
        require(!drivers[msg.sender].isRegistered, "Driver already registered");
        require(emailToAddress[params.email] == address(0), "Email already registered");
        
        // Validate string lengths
        require(bytes(params.vehicleOwnerName).length > 0 && bytes(params.vehicleOwnerName).length <= 100, "Invalid name length");
        require(bytes(params.dateOfBirth).length == 10, "Invalid DOB format");
        require(bytes(params.gender).length > 0 && bytes(params.gender).length <= 10, "Invalid gender");
        require(bytes(params.cnic).length == 15, "CNIC must be 15 characters");
        require(bytes(params.contactNumber).length == 12, "Phone must be 12 characters");
        require(bytes(params.email).length > 0 && bytes(params.email).length <= 100, "Invalid email");
        require(bytes(params.licenseNumber).length > 0 && bytes(params.licenseNumber).length <= 15, "Invalid license");
        require(bytes(params.vehicleRegNumber).length > 0 && bytes(params.vehicleRegNumber).length <= 20, "Invalid reg number");
        require(bytes(params.vehicleType).length > 0 && bytes(params.vehicleType).length <= 20, "Invalid vehicle type");
        require(bytes(params.addressDetails).length > 0 && bytes(params.addressDetails).length <= 200, "Invalid address");
        require(params.passwordHash != 0, "Password required");
        require(bytes(params.profilePictureCID).length > 0, "Profile picture required");
        require(bytes(params.vehiclePictureCID).length > 0, "Vehicle picture required");

        // Register the driver
        drivers[msg.sender] = Driver({
            vehicleOwnerName: params.vehicleOwnerName,
            dateOfBirth: params.dateOfBirth,
            gender: params.gender,
            cnic: params.cnic,
            contactNumber: params.contactNumber,
            email: params.email,
            licenseNumber: params.licenseNumber,
            vehicleRegNumber: params.vehicleRegNumber,
            vehicleType: params.vehicleType,
            addressDetails: params.addressDetails,
            passwordHash: params.passwordHash,
            profilePictureCID: params.profilePictureCID,
            vehiclePictureCID: params.vehiclePictureCID,
            isRegistered: true
        });

        // Update mappings
        emailToAddress[params.email] = msg.sender;
        registeredDrivers.push(msg.sender);

        emit DriverRegistered(msg.sender, params.email);
    }

    /**
     * @dev Retrieves driver details by email
     * @param _email The driver's email
     * @return Driver struct with all details
     */
    function getDriver(string memory _email) public view returns (Driver memory) {
        address driverAddress = emailToAddress[_email];
        require(driverAddress != address(0), "Driver not found");
        return drivers[driverAddress];
    }

    /**
     * @dev Sets driver active/inactive status (only owner)
     * @param _driver The driver's address
     * @param _status New status (true = active, false = inactive)
     */
    function setDriverStatus(address _driver, bool _status) public onlyOwner {
        require(drivers[_driver].isRegistered != _status, "Status already set");
        drivers[_driver].isRegistered = _status;
        emit DriverStatusChanged(_driver, _status);
    }

    /**
     * @dev Updates profile picture (only registered drivers)
     * @param _profilePictureCID New IPFS CID for profile picture
     */
    function updateProfilePicture(string memory _profilePictureCID) public onlyRegisteredDriver {
        require(bytes(_profilePictureCID).length > 0, "Invalid CID");
        drivers[msg.sender].profilePictureCID = _profilePictureCID;
        emit ProfileUpdated(msg.sender, _profilePictureCID);
    }

    /**
     * @dev Updates vehicle picture (only registered drivers)
     * @param _vehiclePictureCID New IPFS CID for vehicle picture
     */
    function updateVehiclePicture(string memory _vehiclePictureCID) public onlyRegisteredDriver {
        require(bytes(_vehiclePictureCID).length > 0, "Invalid CID");
        drivers[msg.sender].vehiclePictureCID = _vehiclePictureCID;
        emit VehicleUpdated(msg.sender, _vehiclePictureCID);
    }

    /**
     * @dev Login verification
     * @param _email The driver's email
     * @param _passwordHash The hashed password
     * @return True if login is successful
     */
    function login(string memory _email, bytes32 _passwordHash) public view returns (bool) {
        address driverAddress = emailToAddress[_email];
        require(driverAddress != address(0), "Driver not found");
        require(drivers[driverAddress].isRegistered, "Driver not active");
        require(
            drivers[driverAddress].passwordHash == _passwordHash,
            "Invalid credentials"
        );
        return true;
    }

    /**
     * @dev Returns count of registered drivers
     */
    function getDriverCount() public view returns (uint256) {
        return registeredDrivers.length;
    }
}