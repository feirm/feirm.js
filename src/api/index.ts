import axios from "axios";

const apiGateway = axios.create({
    baseURL: "https://api.feirm.com",
    headers: {
        "Content-Type": "application/json"
    }
});

export { apiGateway }