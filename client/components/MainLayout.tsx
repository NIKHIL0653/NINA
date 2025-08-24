import { Link, useLocation } from "react-router-dom";
import { useAuth } from "@/lib/auth-context";
import { useUserDisplayName } from "@/hooks/use-user-display-name";
import { useDarkMode } from "@/hooks/use-dark-mode";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  LogOut,
  Stethoscope,
  User,
  Settings,
  ChevronDown,
  MessageCircle,
  FileText,
  BarChart3,
  Moon,
  Sun,
} from "lucide-react";
import { cn } from "@/lib/utils";
import BottomNav from "./BottomNav";

interface MainLayoutProps {
  children: React.ReactNode;
}

export default function MainLayout({ children }: MainLayoutProps) {
  const { user, signOut } = useAuth();
  const { displayName, initials } = useUserDisplayName();
  const { isDark, toggle } = useDarkMode();
  const location = useLocation();

  // Chat-specific header (blue bar with Nina centered)
  const renderChatHeader = () => (
    <nav className="sticky top-0 z-50 bg-blue-400 shadow-sm">
      <div className="h-16 flex items-center justify-center">
        <h1 className="text-xl font-semibold text-white">NINA</h1>
      </div>
    </nav>
  );

  // Records-specific header (title + account)
  const renderRecordsHeader = () => (
    <nav className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          <h1 className="text-xl font-semibold text-foreground">
            Clinical Records
          </h1>

          {/* User Menu */}
          <div className="flex items-center">
            {/* Desktop dropdown */}
            <div className="hidden md:block">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    className="flex items-center space-x-2 px-3 py-1.5 bg-accent/50 rounded-lg hover:bg-accent transition-all duration-300"
                  >
                    <div className="w-6 h-6 bg-blue-400 rounded-full flex items-center justify-center">
                      <span className="text-xs text-white font-semibold">{initials}</span>
                    </div>
                    <ChevronDown className="w-3 h-3 opacity-50" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <div className="px-3 py-2 border-b">
                    <p className="text-sm font-medium">{displayName}</p>
                    <p className="text-xs text-muted-foreground">{user?.email}</p>
                  </div>
                  <DropdownMenuItem asChild>
                    <Link
                      to="/settings"
                      className="flex items-center space-x-2 cursor-pointer"
                    >
                      <Settings className="w-4 h-4" />
                      <span>Settings</span>
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={toggle}
                    className="flex items-center space-x-2 cursor-pointer"
                  >
                    {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                    <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={signOut}
                    className="flex items-center space-x-2 cursor-pointer text-destructive focus:text-destructive"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Sign out</span>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            {/* Mobile account text */}
            <div className="md:hidden flex items-center space-x-2">
              <div className="w-6 h-6 bg-blue-400 rounded-full flex items-center justify-center">
                <span className="text-xs text-white font-semibold">{initials}</span>
              </div>
              <span className="text-sm font-medium text-muted-foreground">
                {displayName}
              </span>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );

  // Default header for other routes (logo + account)
  const renderDefaultHeader = () => (
    <nav className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl overflow-hidden shadow-lg">
              <img
                src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F80852419a0194244b22ef22578b3e48b?format=webp&width=800"
                alt="NINA AI Logo"
                className="w-full h-full object-cover"
              />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-foreground">NINA</h1>
            </div>
          </div>

          {/* Desktop Navigation Links */}
          <div className="hidden md:flex items-center space-x-1 flex-1 justify-center">
            <Link to="/chat">
              <Button
                variant={location.pathname === "/chat" ? "default" : "ghost"}
                size="sm"
                className={cn("relative group transition-all duration-300", location.pathname === "/chat" && "bg-blue-400 hover:bg-blue-500 text-white")}
              >
                <MessageCircle className="w-4 h-4 mr-2" />
                Chat
              </Button>
            </Link>
            <Link to="/records">
              <Button
                variant={location.pathname === "/records" ? "default" : "ghost"}
                size="sm"
                className={cn("relative group transition-all duration-300", location.pathname === "/records" && "bg-blue-400 hover:bg-blue-500 text-white")}
              >
                <FileText className="w-4 h-4 mr-2" />
                Records
              </Button>
            </Link>
            <Link to="/dashboard">
              <Button
                variant={
                  location.pathname === "/dashboard" ? "default" : "ghost"
                }
                size="sm"
                className={cn("relative group transition-all duration-300", location.pathname === "/dashboard" && "bg-blue-400 hover:bg-blue-500 text-white")}
              >
                <BarChart3 className="w-4 h-4 mr-2" />
                News
              </Button>
            </Link>
          </div>

          {/* User Menu */}
          <div className="flex items-center">
            {/* Desktop dropdown */}
            <div className="hidden md:block">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    className="flex items-center space-x-2 px-3 py-1.5 bg-accent/50 rounded-lg hover:bg-accent transition-all duration-300"
                  >
                    <div className="w-6 h-6 bg-blue-400 rounded-full flex items-center justify-center">
                      <span className="text-xs text-white font-semibold">{initials}</span>
                    </div>
                    <ChevronDown className="w-3 h-3 opacity-50" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <div className="px-3 py-2 border-b">
                    <p className="text-sm font-medium">{displayName}</p>
                    <p className="text-xs text-muted-foreground">{user?.email}</p>
                  </div>
                  <DropdownMenuItem asChild>
                    <Link
                      to="/settings"
                      className="flex items-center space-x-2 cursor-pointer"
                    >
                      <Settings className="w-4 h-4" />
                      <span>Settings</span>
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={toggle}
                    className="flex items-center space-x-2 cursor-pointer"
                  >
                    {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                    <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={signOut}
                    className="flex items-center space-x-2 cursor-pointer text-destructive focus:text-destructive"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Sign out</span>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            {/* Mobile account text */}
            <div className="md:hidden flex items-center space-x-2">
              <div className="w-6 h-6 bg-blue-400 rounded-full flex items-center justify-center">
                <User className="w-3 h-3 text-white" />
              </div>
              <span className="text-sm font-medium text-muted-foreground">
                Your account
              </span>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );

  // Settings-specific header (clean header without navigation)
  const renderSettingsHeader = () => (
    <nav className="sticky top-0 z-50 bg-blue-400 shadow-sm">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Title */}
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-xl overflow-hidden shadow-lg">
              <img
                src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F80852419a0194244b22ef22578b3e48b?format=webp&width=800"
                alt="NINA AI Logo"
                className="w-full h-full object-cover"
              />
            </div>
            <h1 className="text-xl font-semibold text-white">Settings</h1>
          </div>

          {/* Profile Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="flex items-center space-x-2 px-3 py-1.5 text-white hover:bg-white/20 rounded-lg transition-all duration-300"
              >
                <div className="w-6 h-6 bg-white/20 rounded-full flex items-center justify-center">
                  <span className="text-xs text-white font-semibold">{initials}</span>
                </div>
                <ChevronDown className="w-3 h-3 opacity-70" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <div className="px-3 py-2 border-b">
                <p className="text-sm font-medium">{displayName}</p>
                <p className="text-xs text-muted-foreground">{user?.email}</p>
              </div>
              <DropdownMenuItem asChild>
                <Link
                  to="/settings"
                  className="flex items-center space-x-2 cursor-pointer"
                >
                  <Settings className="w-4 h-4" />
                  <span>Settings</span>
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={toggle}
                className="flex items-center space-x-2 cursor-pointer"
              >
                {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={signOut}
                className="flex items-center space-x-2 cursor-pointer text-destructive focus:text-destructive"
              >
                <LogOut className="w-4 h-4" />
                <span>Sign out</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </nav>
  );

  // Render appropriate header based on current route
  const renderHeader = () => {
    if (location.pathname === "/chat") {
      return renderChatHeader();
    } else if (location.pathname === "/records") {
      return renderRecordsHeader();
    } else if (location.pathname === "/settings") {
      return renderSettingsHeader();
    } else {
      return renderDefaultHeader();
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Route-specific header */}
      {renderHeader()}

      {/* Main Content */}
      <main className="flex-1">{children}</main>

      {/* Bottom Navigation for Mobile */}
      <BottomNav />
    </div>
  );
}
