import React, { createContext, useContext, useState } from "react";
import { api } from "../api/client";

interface AuthContextType {
  token: string | null;
  adminToken: string | null;
  isAuthenticated: boolean;
  login: (token: string) => Promise<boolean>;
  logout: () => void;
  isLoginModalOpen: boolean;
  openLoginModal: () => void;
  closeLoginModal: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // SECURITY SI-10 & design.md: Token is held in memory ONLY. Never persisted to storage or cookies.
  const [token, setToken] = useState<string | null>(null);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);

  const login = async (candidateToken: string): Promise<boolean> => {
    const trimmed = candidateToken.trim();
    if (!trimmed) return false;

    const isValid = await api.validateAdminToken(trimmed);
    if (isValid) {
      setToken(trimmed);
      setIsLoginModalOpen(false);
      return true;
    }
    return false;
  };

  const logout = () => {
    setToken(null);
  };

  const openLoginModal = () => setIsLoginModalOpen(true);
  const closeLoginModal = () => setIsLoginModalOpen(false);

  return (
    <AuthContext.Provider
      value={{
        token,
        adminToken: token,
        isAuthenticated: !!token,
        login,
        logout,
        isLoginModalOpen,
        openLoginModal,
        closeLoginModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
