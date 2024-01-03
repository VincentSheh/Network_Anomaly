import Image from "next/image";
import TargetField from "./TargetField";
import * as React from "react"

import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

export default function Hero(){
  return (
    <div className="relative py-10">
      <Image
        src="/hero.gif"
        alt="Hero gif"
        width={1920}
        height={1080}
        />
      <TargetField/>
       


    </div>
  )
}