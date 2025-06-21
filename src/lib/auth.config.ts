// lib/auth.config.ts
import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma";
import { comparePassword } from "@/lib/auth";

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Email and Password",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "your@email.com" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null;
        }

        try {
          // Find user in database
          const user = await prisma.user.findUnique({
            where: {
              email: credentials.email.toLowerCase(),
            }
          });

          if (!user || !user.password) {
            return null;
          }

          // Compare password
          const isPasswordValid = await comparePassword(
            credentials.password,
            user.password
          );

          if (!isPasswordValid) {
            return null;
          }

          // Return user object (password excluded)
          const { password, ...userWithoutPassword } = user;
          return {
            ...userWithoutPassword,
            name: user.name || '',
            image: user.image || '',
            emailVerified: user.emailVerified || null,
          };
        } catch (error) {
          console.error("Authentication error:", error);
          return null;
        }
      },
    }),
    
    // Only include Google provider if credentials are available
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET ? [
      GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        authorization: {
          params: {
            prompt: "consent",
            access_type: "offline",
            response_type: "code"
          }
        }
      })
    ] : []),
  ],
  
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  
  callbacks: {
    async jwt({ token, user, account }) {
      // Initial sign in
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.picture = user.image;
      }
      
      // Handle Google OAuth account linking
      if (account?.provider === "google") {
        token.accessToken = account.access_token;
      }
      
      return token;
    },
    
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id as string;
        session.user.email = token.email as string;
        session.user.name = token.name as string;
        session.user.image = token.picture as string;
      }
      return session;
    },
    
    async signIn({ user, account, profile }) {
      // Allow credentials login
      if (account?.provider === "credentials") {
        return true;
      }
      
      // Handle Google OAuth
      if (account?.provider === "google" && profile?.email) {
        try {
          // Check if user exists with this email
          const existingUser = await prisma.user.findUnique({
            where: { email: profile.email.toLowerCase() },
          });

          return true; // Always allow sign in for Google
        } catch (error) {
          console.error("Sign in error:", error);
          return true; // Allow sign in even on error
        }
      }
      
      return true;
    },
  },
  
  pages: {
    signIn: "/login",
    error: "/login",
  },
  
  secret: process.env.NEXTAUTH_SECRET,
  debug: false, // Disable debug in production
};