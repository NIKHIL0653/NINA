import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { Navigate } from "react-router-dom";
import { useDarkMode } from "@/hooks/use-dark-mode";
import { useUserDisplayName } from "@/hooks/use-user-display-name";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import BottomNav from "@/components/BottomNav";
import {
  ExternalLink,
  Clock,
  RefreshCw,
  Newspaper,
  User,
  Settings,
  LogOut,
  ChevronDown,
  Moon,
  Sun,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface NewsItem {
  id: string;
  title: string;
  summary?: string;
  content_text?: string;
  content_html?: string;
  url: string;
  date_published: string;
  author?: {
    name: string;
  };
  tags?: string[];
  image?: string;
}

interface HealthFeed {
  version: string;
  title: string;
  description?: string;
  home_page_url?: string;
  items: NewsItem[];
}

export default function Dashboard() {
  const { user, loading, signOut } = useAuth();
  const { isDark, toggle } = useDarkMode();
  const { displayName, initials } = useUserDisplayName();
  const [newsItems, setNewsItems] = useState<NewsItem[]>([]);
  const [isLoadingNews, setIsLoadingNews] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchHealthcareNews = async () => {
    setIsLoadingNews(true);
    setError(null);
    
    try {
      const response = await fetch('https://rss.app/feeds/v1.1/5rdWM6JSuqb3ZH4h.json');
      
      if (!response.ok) {
        throw new Error('Failed to fetch healthcare news');
      }
      
      const data: HealthFeed = await response.json();
      setNewsItems(data.items || []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Error fetching healthcare news:', err);
      setError('Unable to load latest healthcare news. Please try again later.');
      
      // Fallback to sample news items with images
      setNewsItems([
        {
          id: "1",
          title: "Poor sleep patterns linked to diabetes, dementia, and 170 diseases",
          summary: "A new study has linked 172 different diseases, which include dementia, type 2 diabetes, and cardiovascular conditions to poor sleep patterns and sleep disorders.",
          url: "#",
          date_published: new Date().toISOString(),
          author: { name: "Medical News Today" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "2", 
          title: "3 diets may help lower diabetes risk: What do they have in common?",
          summary: "The Mediterranean, DASH, and AHEI diets can all lower the risk of developing type 2 diabetes, a new meta-analysis suggests.",
          url: "#",
          date_published: new Date(Date.now() - 3600000).toISOString(),
          author: { name: "Nutrition Research Journal" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "3",
          title: "Alzheimer's treatment: Cancer drug combo shows promise in mice",
          summary: "Two already-approved medications may help overturn the brain disease, according to a recent study conducted in laboratory mice.",
          url: "#",
          date_published: new Date(Date.now() - 7200000).toISOString(),
          author: { name: "Neuroscience Today" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "4",
          title: "Breakthrough Gene Therapy Shows Promise for Rare Genetic Disorders",
          summary: "Clinical trials reveal significant improvements in patients with rare genetic conditions using novel gene editing techniques.",
          url: "#",
          date_published: new Date(Date.now() - 10800000).toISOString(),
          author: { name: "Gene Therapy Research" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "5",
          title: "Mental Health Apps Show Effectiveness in Clinical Studies",
          summary: "Recent studies demonstrate that mobile mental health applications can significantly complement traditional therapy approaches.",
          url: "#",
          date_published: new Date(Date.now() - 14400000).toISOString(),
          author: { name: "Digital Health Journal" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "6",
          title: "New Alzheimer's Drug Receives FDA Approval",
          summary: "The FDA approves a promising new treatment for early-stage Alzheimer's disease, offering hope to millions of patients and families.",
          url: "#",
          date_published: new Date(Date.now() - 18000000).toISOString(),
          author: { name: "FDA News Release" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "7",
          title: "Telemedicine Adoption Continues to Rise Post-Pandemic",
          summary: "Healthcare providers report sustained growth in telehealth services, with patient satisfaction rates exceeding pre-pandemic levels.",
          url: "#",
          date_published: new Date(Date.now() - 21600000).toISOString(),
          author: { name: "Healthcare Technology Review" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "8",
          title: "Innovative Cancer Treatment Shows 90% Success Rate",
          summary: "New immunotherapy approach demonstrates remarkable results in clinical trials for multiple cancer types.",
          url: "#",
          date_published: new Date(Date.now() - 25200000).toISOString(),
          author: { name: "Cancer Research Institute" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        },
        {
          id: "9",
          title: "AI-Powered Drug Discovery Accelerates Treatment Development",
          summary: "Artificial intelligence algorithms are reducing drug discovery timelines from years to months, offering faster treatment options.",
          url: "#",
          date_published: new Date(Date.now() - 28800000).toISOString(),
          author: { name: "AI in Medicine Today" },
          image: "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
        }
      ]);
    } finally {
      setIsLoadingNews(false);
    }
  };

  useEffect(() => {
    fetchHealthcareNews();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-primary/20 border-t-primary rounded-full animate-spin"></div>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) {
      return "Just now";
    } else if (diffInHours < 24) {
      return `${diffInHours}h ago`;
    } else {
      const diffInDays = Math.floor(diffInHours / 24);
      return `${diffInDays}d ago`;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Fixed News Header */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-blue-400 shadow-sm">
        <div className="flex items-center justify-between h-16 px-6">

          {/* Heading on the left */}
          <h1 className="text-xl font-semibold text-white">News</h1>

          {/* Right side buttons */}
          <div className="flex items-center space-x-3 flex-1 justify-end">
            {/* Refresh Button */}
            <div className="flex items-center space-x-2">
              {lastUpdated && (
                <div className="hidden sm:flex items-center space-x-1 text-xs text-white/80">
                  <Clock className="w-3 h-3" />
                  <span>{formatTimeAgo(lastUpdated.toISOString())}</span>
                </div>
              )}
              <Button
                onClick={fetchHealthcareNews}
                disabled={isLoadingNews}
                variant="ghost"
                size="sm"
                className="text-white hover:bg-white/20 h-8 w-8 p-0"
              >
                <RefreshCw className={cn("w-4 h-4", isLoadingNews && "animate-spin")} />
              </Button>
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
                  <a
                    href="/settings"
                    className="flex items-center space-x-2 cursor-pointer"
                  >
                    <Settings className="w-4 h-4" />
                    <span>Settings</span>
                  </a>
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

      {/* Main Content */}
      <div className="pt-16 pb-20">
        <div className="max-w-7xl mx-auto p-4 sm:p-6">
          {/* Error Message */}
          {error && (
            <Card className="border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20 mb-6">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2 text-red-700 dark:text-red-400">
                  <ExternalLink className="w-4 h-4" />
                  <span>{error}</span>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Loading State */}
          {isLoadingNews && (
            <div className="text-center py-12">
              <div className="w-8 h-8 border-2 border-primary/20 border-t-primary rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-muted-foreground">Loading latest healthcare news...</p>
            </div>
          )}

          {/* 3-Column News Grid */}
          {!isLoadingNews && newsItems.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-h-[calc(100vh-200px)] overflow-y-auto pr-2">
              {newsItems.map((item) => (
                <Card 
                  key={item.id} 
                  className="group hover:shadow-lg transition-all duration-300 cursor-pointer overflow-hidden border border-gray-200 dark:border-gray-700 h-fit"
                  onClick={() => window.open(item.url, '_blank')}
                >
                  {/* Image */}
                  <div className="w-full h-48 bg-gray-100 dark:bg-gray-800">
                    <img
                      src={item.image || "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"}
                      alt={item.title}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                    />
                  </div>
                  
                  {/* Content */}
                  <CardContent className="p-4">
                    <div className="space-y-3">
                      <h3 className="text-lg font-semibold text-foreground group-hover:text-blue-400 transition-colors duration-200 line-clamp-3 leading-tight">
                        {item.title}
                      </h3>
                      
                      <p className="text-muted-foreground text-sm line-clamp-3 leading-relaxed">
                        {item.summary || item.content_text || "Read more to discover the latest healthcare insights..."}
                      </p>
                      
                      <div className="flex items-center justify-between pt-2 border-t border-gray-100 dark:border-gray-800">
                        <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                          <Clock className="w-3 h-3" />
                          <span>{formatTimeAgo(item.date_published)}</span>
                        </div>
                        <Button size="sm" variant="ghost" className="group-hover:bg-blue-50 dark:group-hover:bg-blue-900/20 p-1 h-auto">
                          <ExternalLink className="w-3 h-3" />
                        </Button>
                      </div>
                      
                      {item.author && (
                        <div className="text-xs text-muted-foreground font-medium">
                          {item.author.name}
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* No Content State */}
          {!isLoadingNews && newsItems.length === 0 && !error && (
            <div className="text-center py-12">
              <Newspaper className="w-16 h-16 mx-auto text-muted-foreground mb-4" />
              <h3 className="text-xl font-semibold text-foreground mb-2">No news available</h3>
              <p className="text-muted-foreground">
                No healthcare news available at the moment.
              </p>
              <Button 
                onClick={fetchHealthcareNews}
                variant="outline"
                className="mt-4"
              >
                Try Again
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Bottom Navigation */}
      <BottomNav />
    </div>
  );
}
