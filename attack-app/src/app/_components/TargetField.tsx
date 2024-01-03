"use client"
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


export default async function TargetField() {
  const handleCheck = async () => {
    const response = await fetch('/api/attacks');
    // const data = await response.text();
    // console.log(data);

  }
  return (
    <Card className="absolute w-[700px] z-50 top-1/2 transform  -translate-y-1/2 bg-white bg-opacity-90 text-black border border-gray-300 shadow-lg">
    <CardHeader>
      <CardTitle>Attack a device</CardTitle>
      <CardDescription>Make sure you have the device owner's consent before attacking</CardDescription>
    </CardHeader>
    <CardContent>
      <form>
        <div className="grid w-full items-center gap-4">
          <div className="flex flex-col space-y-1.5">
            <Label htmlFor="target">Target</Label>
            <Input id="target" placeholder="TODO: Check IP Validity" />
          </div>

        </div>
      </form>
    </CardContent>
    <CardFooter className="flex justify-between">
      <Button onClick={handleCheck} variant="outline">Check</Button>
    </CardFooter>
  </Card>      

  )
}
