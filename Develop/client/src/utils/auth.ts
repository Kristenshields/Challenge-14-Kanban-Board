import { JwtPayload, jwtDecode } from 'jwt-decode';

class AuthService {
  getProfile() {
    // TODO: return the decoded token
    return jwtDecode(this.getToken()) as JwtPayload;

  }

  loggedIn() {
    // TODO: return a value that indicates if the user is logged in
    return this.getToken() ? true : false;
  }
  
  isTokenExpired(token: string) {
    // TODO: return a value that indicates if the token is expired
    const decoded = jwtDecode(token) as JwtPayload;

    if (decoded.exp && decoded.exp * 1000 < Date.now()) {
      return true;
    }
  } catch (error) {
    return false;
  }


  getToken(): string {
    // TODO: return the token
    const token = localStorage.getItem('token');
    if (token && !this.isTokenExpired(token)) {
      return token;
    }
  }

  login(idToken: string) {
    // TODO: set the token to localStorage
    // TODO: redirect to the home page
    localStorage.setItem('token', idToken);
    window.location.assign('/');
  }

  logout() {
    // TODO: remove the token from localStorage
    // TODO: redirect to the login page
    localStorage.removeItem('token');
    window.location.assign('/login');
  }
}

export default new AuthService();