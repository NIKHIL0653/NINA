import { Link, useLocation } from "react-router-dom";
import { MessageCircle, FileText, BarChart3 } from "lucide-react";
import { cn } from "@/lib/utils";

const BottomNav = () => {
  const location = useLocation();

  const navigation = [
    {
      name: "Chat",
      href: "/chat",
      icon: MessageCircle,
      current: location.pathname === "/chat",
    },
    {
      name: "Records",
      href: "/records",
      icon: FileText,
      current: location.pathname === "/records",
    },
    {
      name: "News",
      href: "/dashboard",
      icon: BarChart3,
      current: location.pathname === "/dashboard",
    },
  ];

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50 bg-background border-t border-border h-20">
      <div className="flex items-center justify-center h-full">
        <div className="flex items-center justify-around w-full max-w-md px-4">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.name}
                to={item.href}
                className={cn(
                  "flex flex-col items-center justify-center space-y-1 p-2 min-w-[60px] transition-all duration-300",
                  item.current
                    ? "text-blue-400 font-semibold"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="w-5 h-5" />
                <span className="text-xs font-medium">{item.name}</span>
              </Link>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default BottomNav;
