import { AxiosResponse } from "axios";
import { apiGateway } from "../api";

export default {
    CheckUsername(username: string): Promise<AxiosResponse> {
        return apiGateway.post("auth/v1/check-username", {
            username
        });
    }
}