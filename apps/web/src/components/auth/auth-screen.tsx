import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import type { ReactNode } from "react";

export function AuthScreen({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-[80svh] min-w-0 items-center justify-center px-4 py-8">
      {children}
    </div>
  );
}

export function AuthCard({
  title,
  description,
  children,
}: {
  title: string;
  description: ReactNode;
  children: ReactNode;
}) {
  return (
    <AuthScreen>
      <Card className="w-full min-w-0 max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="font-heading text-2xl tracking-tight">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">{children}</CardContent>
      </Card>
    </AuthScreen>
  );
}
